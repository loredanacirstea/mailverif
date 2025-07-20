package forward

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/mail"
	"slices"
	"strings"
	"time"

	"github.com/loredanacirstea/mailverif/arc"
	"github.com/loredanacirstea/mailverif/dkim"
	"github.com/loredanacirstea/mailverif/dns"
	message "github.com/loredanacirstea/mailverif/utils"
	moxio "github.com/loredanacirstea/mailverif/utils"
	utils "github.com/loredanacirstea/mailverif/utils"
)

const (
	FORWARD_AUTH_HEADER            = "Provable-Authentication-Results"
	HEADER_FORWARD_DNS_REGISTRY    = "Provable-DNS-Registry"
	HEADER_FORWARD_EMAIL_REGISTRY  = "Provable-Email-Registry"
	HEADER_FORWARD_ORIGIN_DKIM_CTX = "Provable-Forward-Origin-DKIM-Context"
	HEADER_FORWARD_SIG             = "Provable-Forward-Signature"
	HEADER_FORWARD_SEAL            = "Provable-Forward-Seal"
)

var (
	FORWARD_AUTH_HEADER_LOWER            = strings.ToLower(FORWARD_AUTH_HEADER)
	HEADER_FORWARD_DNS_REGISTRY_LOWER    = strings.ToLower(HEADER_FORWARD_DNS_REGISTRY)
	HEADER_FORWARD_EMAIL_REGISTRY_LOWER  = strings.ToLower(HEADER_FORWARD_EMAIL_REGISTRY)
	HEADER_FORWARD_ORIGIN_DKIM_CTX_LOWER = strings.ToLower(HEADER_FORWARD_ORIGIN_DKIM_CTX)
	HEADER_FORWARD_SIG_LOWER             = strings.ToLower(HEADER_FORWARD_SIG)
	HEADER_FORWARD_SEAL_LOWER            = strings.ToLower(HEADER_FORWARD_SEAL)
)

var (
	FIELD_DNS_REGISTRY   = "dnsregistry"
	FIELD_EMAIL_REGISTRY = "emailregistry"

	DNS_REGISTRY   = "someurl"
	EMAIL_REGISTRY = "someurl"
)

var (
	ErrMissingFields       = errors.New("missing forward fields")
	ErrInstanceMismatch    = errors.New("mismatch of forward header instances")
	ErrArcLimit            = errors.New("message over forward-set limit")
	ErrMsgNotSigned        = errors.New("message is not forward signed")
	ErrCSValidationFailure = errors.New("most recent Provable-Forward-Signature did not validate")
)

type ArcResult struct {
	// Final result of verification
	Result       dkim.Result
	OriginalDKIM dkim.Result `json:"original-dkim"`

	// Result data at each part of the chain until failure
	Chain []ArcSetResult `json:"chain"`
}

// ArcSetResult holds the result data for verification of a single arc set
type ArcSetResult struct {
	Instance       int         `json:"instance"`
	Spf            dkim.Status `json:"spf"`
	Dkim           dkim.Status `json:"dkim"`
	Dmarc          dkim.Status `json:"dmarc"`
	CV             dkim.Status `json:"cv"`
	ChainSigValid  bool        `json:"forward-chain-signature-valid"`
	ChainSealValid bool        `json:"forward-chain-seal-valid"`
}

var (
	HEADER_NAMES = []string{FORWARD_AUTH_HEADER, HEADER_FORWARD_SIG, HEADER_FORWARD_SEAL}
	SPECS        = []dkim.Spec{AuthResultsSpec, ForwardSignatureSpec, SealSpec}
)

func Verify(elog *slog.Logger, resolver dns.Resolver, smtputf8 bool, r io.ReaderAt, ignoreTest, strictExpiration bool, now func() time.Time, rec *dkim.Record) (*ArcResult, error) {
	hdrs, bodyOffset, err := utils.ParseHeaders(bufio.NewReader(&moxio.AtReader{R: r}))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", dkim.ErrHeaderMalformed, err)
	}
	rawBody, err := io.ReadAll(bufio.NewReader(&moxio.AtReader{R: r, Offset: int64(bodyOffset)}))
	if err != nil {
		return nil, err
	}

	if len(hdrs) == 0 {
		return &ArcResult{Result: dkim.Result{Status: dkim.StatusNone}}, nil
	}
	// TODO verify HEADER_FORWARD_ORIGIN_DKIM_CTX
	originDKIM := dkim.Result{Status: dkim.StatusPass}

	status, results, err := arc.VerifySignaturesBasic(elog, resolver, hdrs, bufio.NewReader(bytes.NewReader(rawBody)), HEADER_NAMES, SPECS, smtputf8, ignoreTest, now, rec)
	if err != nil {
		return &ArcResult{Result: dkim.Result{Status: status, Err: err}, OriginalDKIM: originDKIM}, nil
	}

	chain := []ArcSetResult{}

	// check auth results
	for _, ress := range results {
		res := ArcSetResult{Instance: int(ress[0].Sig.Instance)}
		for _, tags := range ress[0].Sig.Tags {
			for _, tag := range tags {
				switch tag.Key {
				case "dkim":
					v := dkim.Status(tag.Value)
					if string(res.Dkim) == "" || v == dkim.StatusPass {
						res.Dkim = v
					}
				case "dmarc":
					v := dkim.Status(tag.Value)
					res.Dmarc = v
				case "spf":
					v := dkim.Status(tag.Value)
					res.Spf = v
				}
			}
		}
		for _, tags := range ress[2].Sig.Tags {
			for _, tag := range tags {
				switch tag.Key {
				case "cv":
					res.CV = dkim.Status(tag.Value)
				}
			}
		}
		res.ChainSigValid = ress[1].Status == dkim.StatusPass
		res.ChainSealValid = ress[2].Status == dkim.StatusPass
		chain = append(chain, res)
	}

	arcResult := func(result dkim.Status, msg string, i int) *ArcResult {
		return &ArcResult{Result: dkim.Result{Status: result, Err: fmt.Errorf("i=%d %s", i, msg), Index: i}, Chain: chain, OriginalDKIM: originDKIM}
	}

	if !chain[0].ChainSigValid {
		return arcResult(dkim.StatusFail, "Most recent Provable-Forward-Signature did not validate", chain[0].Instance), nil
	}

	// Validate results
	//
	//	"The "cv" value for all ARC-Seal header fields MUST NOT be
	//	"fail".  For ARC Sets with instance values > 1, the values
	//	MUST be "pass".  For the ARC Set with instance value = 1, the
	//	value MUST be "none"."
	for _, res := range chain {
		switch {
		case res.CV == dkim.StatusFail:
			return arcResult(dkim.StatusFail, "ARC-Seal reported failure, the chain is terminated", res.Instance), nil
		case !res.ChainSigValid:
			return arcResult(dkim.StatusFail, "ARC-Seal did not validate", res.Instance), nil
		case (res.Instance == 1) && (res.CV != dkim.StatusNone):
			return arcResult(dkim.StatusFail, "ARC-Seal reported invalid status", res.Instance), nil
		case (res.Instance > 1) && (res.CV != dkim.StatusPass):
			return arcResult(dkim.StatusFail, "ARC-Seal reported invalid status", res.Instance), nil
		}
	}

	return &ArcResult{Result: dkim.Result{Status: dkim.StatusPass}, Chain: chain, OriginalDKIM: originDKIM}, nil
}

func Forward(
	elog *slog.Logger, resolver dns.Resolver,
	domain dns.Domain, selectors []dkim.Selector,
	smtputf8 bool,
	msg io.ReaderAt,
	mailfrom string, ipfrom string,
	from *mail.Address, to []*mail.Address, cc []*mail.Address, bcc []*mail.Address,
	subject string, timestamp time.Time,
	ignoreTest bool, strictExpiration bool, now func() time.Time, rec *dkim.Record,
) ([]utils.Header, io.Reader, error) {
	// envelope sender or MAIL FROM address, is set by the email client or server initiating the SMTP transaction
	hdrsOriginal, bodyOffset, err := utils.ParseHeaders(bufio.NewReader(&moxio.AtReader{R: msg}))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s", dkim.ErrHeaderMalformed, err)
	}
	rawBody, err := io.ReadAll(bufio.NewReader(&moxio.AtReader{R: msg, Offset: int64(bodyOffset)}))
	if err != nil {
		return nil, nil, err
	}
	hdrsForward, err := BuildForwardHeaders(elog, smtputf8, msg, hdrsOriginal, from, to, cc, bcc, subject, timestamp)
	if err != nil {
		return nil, nil, err
	}

	addlHeaders, err := Sign(elog, resolver, domain, selectors, smtputf8, hdrsOriginal, hdrsForward, rawBody, mailfrom, ipfrom, ignoreTest, strictExpiration, now, rec)
	if err != nil {
		return nil, nil, err
	}
	br := bufio.NewReader(bytes.NewReader(rawBody))
	return AppendForwardHeaders(hdrsForward, addlHeaders), br, nil
}

func AppendForwardHeaders(hdrs []utils.Header, addlHeaders []utils.Header) []utils.Header {
	slices.Reverse(addlHeaders)
	return append(addlHeaders, hdrs...)
}

func Sign(elog *slog.Logger, resolver dns.Resolver, domain dns.Domain, selectors []dkim.Selector, smtputf8 bool, hdrsOriginal []utils.Header, hdrsForward []utils.Header, rawBody []byte, mailfrom string, ipfrom string, ignoreTest bool, strictExpiration bool, now func() time.Time, rec *dkim.Record) ([]utils.Header, error) {
	// envelope sender or MAIL FROM address, is set by the email client or server initiating the SMTP transaction
	if len(hdrsOriginal) == 0 {
		return nil, fmt.Errorf("no original headers")
	}
	if len(hdrsForward) == 0 {
		return nil, fmt.Errorf("no forwarded headers")
	}

	arcSets, err := arc.ExtractSignatureSets(hdrsOriginal, HEADER_NAMES, SPECS, smtputf8)
	if err != nil {
		return nil, err
	}
	instance := len(arcSets) + 1

	signedHeaders := []utils.Header{}

	_selectors := make([]dkim.Selector, len(selectors))
	copy(_selectors, selectors)

	// dkim checks
	dkimResults, err := dkim.Verify(elog, resolver, smtputf8, dkim.DKIMSpec.PolicySig, hdrsOriginal, bufio.NewReader(bytes.NewReader(rawBody)), ignoreTest, strictExpiration, now, rec)
	if err != nil {
		return nil, err
	}

	// auth checks
	from, err := arc.GetFrom(hdrsOriginal)
	if err != nil {
		return nil, err
	}
	headerFrom := strings.Split(from.Address, "@")[1]
	spfRes, dmarcPass, cv := arc.BuildAuthResults(from, mailfrom, ipfrom, dkimResults, instance, resolver)

	sigsAuth, err := dkim.BuildSignatureGeneric(elog, AuthResultsSpec, hdrsForward, bufio.NewReader(bytes.NewReader(rawBody)), domain, _selectors, smtputf8, now)
	if err != nil {
		return nil, err
	}
	sigsAuth[0].Instance = int32(instance)
	tags := arc.BuildAuthenticationResultTags(domain, mailfrom, headerFrom, dkimResults, spfRes, dmarcPass)
	sigsAuth[0].Tags = tags

	headers, err := dkim.SignGeneric(AuthResultsSpec, sigsAuth, hdrsForward, nil)
	if err != nil {
		return nil, err
	}
	sigsAuth[0].HeaderFull.Raw = headers[0].Raw
	signedHeaders = append(signedHeaders, headers...)

	_selectors = make([]dkim.Selector, len(selectors))
	copy(_selectors, selectors)
	sigsMS, err := dkim.BuildSignatureGeneric(elog, ForwardSignatureSpec, hdrsForward, bufio.NewReader(bytes.NewReader(rawBody)), domain, _selectors, smtputf8, now)
	if err != nil {
		return nil, err
	}
	sigsMS[0].Instance = int32(instance)
	sigsMS[0].Tags = append(sigsMS[0].Tags, []dkim.Tag{{Key: FIELD_DNS_REGISTRY, Value: DNS_REGISTRY}})
	sigsMS[0].Tags = append(sigsMS[0].Tags, []dkim.Tag{{Key: FIELD_EMAIL_REGISTRY, Value: EMAIL_REGISTRY}})
	headers, err = dkim.SignGeneric(ForwardSignatureSpec, sigsMS, hdrsForward, nil)
	if err != nil {
		return nil, err
	}
	sigsMS[0].HeaderFull.Raw = headers[0].Raw
	signedHeaders = append(signedHeaders, headers...)

	// seal
	arcSets = append(arcSets, arc.ArcSet{Sigs: []*dkim.Sig{sigsAuth[0], sigsMS[0]}, I: instance})
	prefixed := arc.GetChainHeaders(arcSets, instance-1)

	_selectors = make([]dkim.Selector, len(selectors))
	copy(_selectors, selectors)
	sigsAS, err := dkim.BuildSignatureGeneric(elog, SealSpec, hdrsForward, bufio.NewReader(bytes.NewReader(rawBody)), domain, _selectors, smtputf8, now)
	if err != nil {
		return nil, err
	}
	sigsAS[0].Instance = int32(instance)
	sigsAS[0].Tags = [][]dkim.Tag{{{Key: "cv", Value: cv}}}
	headers, err = dkim.SignGeneric(SealSpec, sigsAS, hdrsForward, prefixed)
	if err != nil {
		return nil, err
	}
	signedHeaders = append(signedHeaders, headers...)
	return signedHeaders, nil
}

var SealSpec = dkim.Spec{
	HeaderName:             HEADER_FORWARD_SEAL,
	RequiredTags:           []string{"a", "b", "d", "s", "i", "cv"},
	HeaderCanonicalization: "relaxed",
	BodyCanonicalization:   "relaxed",
	PolicySig:              PolicyArcSeal,
	PolicyHeader:           PolicyHeadersArcSeal,
	PolicyParsing:          PolicyParsingArcSeal,
	CheckSignatureParams:   CheckSignatureParamsArcSeal,
	NewSigWithDefaults:     NewSigWithDefaultsArcSeal,
	BuildSignatureHeader:   BuildHeaderAS,
	RequiredHeaders:        []string{},
}

var ForwardSignatureSpec = dkim.Spec{
	HeaderName:             HEADER_FORWARD_SIG,
	RequiredTags:           []string{"a", "b", "bh", "d", "h", "s", "i"},
	HeaderCanonicalization: "relaxed",
	BodyCanonicalization:   "relaxed",
	PolicySig:              PolicyArcMS,
	PolicyHeader:           PolicyHeadersArcMS,
	PolicyParsing:          PolicyParsingArcMS,
	CheckSignatureParams:   CheckSignatureParamsArcMS,
	NewSigWithDefaults:     NewSigWithDefaultsArcMS,
	BuildSignatureHeader:   BuildHeaderMS,
	// ParseSignature:         ParseForwardSignature,
	RequiredHeaders: append(strings.Split("From,To,Cc,Bcc,Reply-To,References,In-Reply-To,Subject,Date,Message-ID,Content-Type", ","), HEADER_FORWARD_DNS_REGISTRY, HEADER_FORWARD_EMAIL_REGISTRY, HEADER_FORWARD_ORIGIN_DKIM_CTX),
}

var AuthResultsSpec = dkim.Spec{
	HeaderName:             FORWARD_AUTH_HEADER,
	RequiredTags:           arc.AuthResultsSpec.RequiredTags,
	HeaderCanonicalization: arc.AuthResultsSpec.HeaderCanonicalization,
	BodyCanonicalization:   arc.AuthResultsSpec.BodyCanonicalization,
	PolicySig:              arc.AuthResultsSpec.PolicySig,
	PolicyHeader:           arc.AuthResultsSpec.PolicyHeader,
	PolicyParsing:          arc.AuthResultsSpec.PolicyParsing,
	CheckSignatureParams:   arc.AuthResultsSpec.CheckSignatureParams,
	NewSigWithDefaults:     arc.AuthResultsSpec.NewSigWithDefaults,
	ParseSignature:         arc.AuthResultsSpec.ParseSignature,
	BuildSignatureHeader:   arc.AuthResultsSpec.BuildSignatureHeader,
	RequiredHeaders:        arc.AuthResultsSpec.RequiredHeaders,
	GetPrefixHeaders:       arc.AuthResultsSpec.GetPrefixHeaders,
}

func NewSigWithDefaultsArcSeal() *dkim.Sig {
	return &dkim.Sig{
		Canonicalization: "relaxed/relaxed",
		Length:           -1,
		SignTime:         -1,
		ExpireTime:       -1,
	}
}

func PolicyArcSeal(sig *dkim.Sig) error {
	return nil
}

func PolicyHeadersArcSeal(hdrs []utils.Header) error {
	return nil
}

func PolicyParsingArcSeal(ds *dkim.Sig, p *dkim.Parser, fieldName string) (bool, error) {
	switch fieldName {
	case "i":
		ds.Instance = int32(p.XNumber(2))
		return true, nil
	}
	return false, nil
}

func CheckSignatureParamsArcSeal(sig *dkim.Sig) error {
	return nil
}

func NewSigWithDefaultsArcMS() *dkim.Sig {
	return &dkim.Sig{
		Canonicalization: "relaxed/relaxed",
		Length:           -1,
		SignTime:         -1,
		ExpireTime:       -1,
	}
}

func PolicyArcMS(sig *dkim.Sig) error {
	return nil
}

func PolicyHeadersArcMS(hdrs []utils.Header) error {
	return nil
}

func PolicyParsingArcMS(ds *dkim.Sig, p *dkim.Parser, fieldName string) (bool, error) {
	switch fieldName {
	case "i":
		ds.Instance = int32(p.XNumber(2))
		return true, nil
	case DNS_REGISTRY:
		ds.Tags = append(ds.Tags, []dkim.Tag{{Key: DNS_REGISTRY, Value: p.StatusValue()}})
	case EMAIL_REGISTRY:
		ds.Tags = append(ds.Tags, []dkim.Tag{{Key: EMAIL_REGISTRY, Value: p.StatusValue()}})
	}
	return false, nil
}

func CheckSignatureParamsArcMS(sig *dkim.Sig) error {
	return nil
}

func extractFSTags(s *dkim.Sig) map[string]string {
	results := map[string]string{}
	for _, t := range s.Tags {
		for _, v := range t {
			if v.Key == FIELD_DNS_REGISTRY {
				results[FIELD_DNS_REGISTRY] = v.Value
				continue
			}
			if v.Key == FIELD_EMAIL_REGISTRY {
				results[FIELD_EMAIL_REGISTRY] = v.Value
				continue
			}
		}
	}
	return results
}

func BuildHeaderMS(s *dkim.Sig) (string, error) {
	res := extractFSTags(s)

	w := &message.HeaderWriter{}
	w.Addf("", "%s: i=%d;", s.HeaderFull.Key, s.Instance)

	// Domain names must always be in ASCII. ../rfc/6376:1115 ../rfc/6376:1187 ../rfc/6376:1303
	s.BuildDomain(w)
	s.BuildSelector(w)
	s.BuildAlgorithm(w)
	s.BuildCanonicalization(w)
	s.BuildQueryMethods(w)
	// s.BuildSignTime(w)
	// s.BuildExpireTime(w)
	s.BuildSignedHeaders(w)
	s.BuildBh(w)
	w.Addf(" ", "%s=%s;", FIELD_DNS_REGISTRY, res[FIELD_DNS_REGISTRY])
	w.Addf(" ", "%s=%s;", FIELD_EMAIL_REGISTRY, res[FIELD_EMAIL_REGISTRY])
	s.BuildSignature(w)

	w.Add("\r\n")
	return w.String(), nil
}

func BuildHeaderAS(s *dkim.Sig) (string, error) {
	cv := ""
	for _, t := range s.Tags {
		for _, v := range t {
			if v.Key == "cv" {
				cv = v.Value
				break
			}
		}
	}

	w := &message.HeaderWriter{}
	w.Addf("", "%s: i=%d;", s.HeaderFull.Key, s.Instance)

	// Domain names must always be in ASCII. ../rfc/6376:1115 ../rfc/6376:1187 ../rfc/6376:1303
	s.BuildDomain(w)
	s.BuildSelector(w)
	s.BuildAlgorithm(w)
	w.Addf(" ", "cv=%s;", cv)
	s.BuildSignTime(w)
	s.BuildSignature(w)

	w.Add("\r\n")
	return w.String(), nil
}

func BuildForwardHeaders(
	elog *slog.Logger,
	smtputf8 bool,
	originalEmail io.ReaderAt,
	hdrs []utils.Header,
	from *mail.Address,
	to []*mail.Address,
	cc []*mail.Address,
	bcc []*mail.Address,
	subjectAddl string,
	timestamp time.Time,
) ([]utils.Header, error) {
	arcSets, err := arc.ExtractSignatureSets(hdrs, HEADER_NAMES, SPECS, smtputf8)
	if err != nil {
		return nil, err
	}
	instance := len(arcSets) + 1

	hdrs = BuildForwardHeadersInternal(elog, originalEmail, hdrs, from, to, cc, bcc, subjectAddl, timestamp, instance)
	return hdrs, nil
}

func BuildForwardHeadersInternal(
	elog *slog.Logger,
	originalEmail io.ReaderAt,
	hdrs []utils.Header,
	from *mail.Address,
	to []*mail.Address,
	cc []*mail.Address,
	bcc []*mail.Address,
	subjectAddl string,
	timestamp time.Time,
	instance int,
) []utils.Header {
	// changed headers
	updatedHeaders := []string{
		HEADER_FROM,
		HEADER_TO,
		HEADER_CC,
		HEADER_BCC,
		HEADER_DATE,
		HEADER_MESSAGE_ID,
		HEADER_SUBJECT,
		HEADER_REFERENCES,
		HEADER_IN_REPLY_TO,
	}

	// addedHeaders := updatedHeaders
	messageId := ""
	dkimCtxParams := make(map[string]string, 0)
	hdrs2 := make([]utils.Header, 0)
	headers := make([]utils.Header, 0)

	for _, h := range hdrs {
		switch strings.ToLower(h.Key) {
		case HEADER_LOW_MESSAGE_ID:
			messageId = h.GetValueTrimmed() // with <>
			dkimCtxParams[HEADER_LOW_MESSAGE_ID] = messageId
		default:
			hdrs2 = append(hdrs2, h)
		}
	}

	// we replace these headers
	for _, h := range hdrs2 {
		changed := true
		originalValue := h.GetValueTrimmed()
		switch h.LKey {
		case HEADER_LOW_SUBJECT:
			h.Value = []byte(" Re: " + originalValue + ": " + subjectAddl + utils.CRLF) // TODO add from.toAddress()
		case HEADER_LOW_IN_REPLY_TO:
			h.Value = []byte(" " + messageId + utils.CRLF) // with <>
		case HEADER_LOW_REFERENCES: // TODO add all previous references
			h.Value = []byte(" " + messageId + utils.CRLF) // with <>
		case HEADER_LOW_FROM:
			h.Value = []byte(" " + from.String() + utils.CRLF)
		case HEADER_LOW_TO:
			h.Value = []byte(" " + SerializeAddresses(to) + utils.CRLF)
		case HEADER_LOW_CC:
			h.Value = []byte(" " + SerializeAddresses(cc) + utils.CRLF)
		case HEADER_LOW_BCC:
			h.Value = []byte(" " + SerializeAddresses(bcc) + utils.CRLF)
		case HEADER_LOW_DATE:
			h.Value = []byte(" " + timestamp.UTC().Format(time.RFC1123Z) + utils.CRLF)
		// case HEADER_LOW_MESSAGE_ID:
		// 	continue
		default:
			changed = false
			if h.LKey == HEADER_LOW_MIME_VERSION {
				h.Key = HEADER_MIME_VERSION
			}
		}

		if slices.Contains(updatedHeaders, h.Key) {
			if _, ok := dkimCtxParams[h.LKey]; !ok {
				dkimCtxParams[h.LKey] = originalValue
			}
		}

		if changed {
			h.RebuildRaw()
		}

		headers = append(headers, h)
	}
	headers = append([]utils.Header{BuildDkimContextParams(dkimCtxParams, instance)}, headers...)
	return headers
}

func BuildDkimContextParams(dkimCtxParams map[string]string, instance int) utils.Header {
	w := &message.HeaderWriter{}
	w.Addf("", " i=%d;", instance)

	utils.RangeSorted(dkimCtxParams, func(k, v string) {
		w.Addf(" ", "%s=%s;", k, v)
	})

	h := utils.Header{
		Key:   HEADER_FORWARD_ORIGIN_DKIM_CTX,
		LKey:  strings.ToLower(HEADER_FORWARD_ORIGIN_DKIM_CTX),
		Value: []byte(w.String()),
	}
	h.RebuildRaw()
	return h
}

func SerializeAddresses(addresses []*mail.Address) string {
	addrs := make([]string, len(addresses))
	for i, addr := range addresses {
		addrs[i] = addr.String()
	}
	return strings.Join(addrs, ", ")
}
