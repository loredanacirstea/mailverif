package forward

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/mail"
	"net/url"
	"slices"
	"strconv"
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
	HEADER_FORWARD_PREFIX   = "Provable-"
	FORWARD_AUTH_HEADER     = "Provable-Authentication-Results"
	HEADER_FORWARD_DKIM_CTX = "Provable-Forward-DKIM-Context"
	HEADER_FORWARD_SIG      = "Provable-Forward-Signature"
	HEADER_FORWARD_SEAL     = "Provable-Forward-Seal"
)

var (
	FORWARD_AUTH_HEADER_LOWER     = strings.ToLower(FORWARD_AUTH_HEADER)
	HEADER_FORWARD_DKIM_CTX_LOWER = strings.ToLower(HEADER_FORWARD_DKIM_CTX)
	HEADER_FORWARD_SIG_LOWER      = strings.ToLower(HEADER_FORWARD_SIG)
	HEADER_FORWARD_SEAL_LOWER     = strings.ToLower(HEADER_FORWARD_SEAL)
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
	Result dkim.Result

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
	DkimSource     dkim.Status `json:"dkim_source"`
}

var (
	HEADER_NAMES  = []string{HEADER_FORWARD_DKIM_CTX, FORWARD_AUTH_HEADER, HEADER_FORWARD_SIG, HEADER_FORWARD_SEAL}
	SPECS         = []dkim.Spec{DkimCtxSpec, AuthResultsSpec, ForwardSignatureSpec, SealSpec}
	DkimCtxNdx    = 0
	AuthNdx       = 1
	SigNdx        = 2
	ChainNdx      = 3
	DkimSourceNdx = 4
)

func Verify(elog *slog.Logger, resolver dns.Resolver, smtputf8 bool, bodybz []byte, ignoreTest, strictExpiration bool, now func() time.Time, rec *dkim.Record) (*ArcResult, error) {
	r := bytes.NewReader(bodybz)
	hdrs, bodyOffset, err := utils.ParseHeaders(bufio.NewReader(&moxio.AtReader{R: r}))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", dkim.ErrHeaderMalformed, err)
	}
	r = bytes.NewReader(bodybz)
	rawBody, err := io.ReadAll(bufio.NewReader(&moxio.AtReader{R: r, Offset: int64(bodyOffset)}))
	if err != nil {
		return nil, err
	}

	if len(hdrs) == 0 {
		return &ArcResult{Result: dkim.Result{Status: dkim.StatusNone}}, nil
	}

	status, results, err := VerifySignaturesBasic(elog, resolver, hdrs, rawBody, HEADER_NAMES, SPECS, smtputf8, ignoreTest, now, rec)
	if err != nil {
		return &ArcResult{Result: dkim.Result{Status: status, Err: err}}, nil
	}

	chain := []ArcSetResult{}

	// check auth results
	for _, ress := range results {
		res := ArcSetResult{Instance: int(ress[AuthNdx].Sig.Instance)}
		for _, tags := range ress[AuthNdx].Sig.Tags {
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
		for _, tags := range ress[ChainNdx].Sig.Tags {
			for _, tag := range tags {
				switch tag.Key {
				case "cv":
					res.CV = dkim.Status(tag.Value)
				}
			}
		}
		res.ChainSigValid = ress[SigNdx].Status == dkim.StatusPass
		res.ChainSealValid = ress[ChainNdx].Status == dkim.StatusPass
		res.DkimSource = ress[DkimSourceNdx].Status
		chain = append(chain, res)
	}

	arcResult := func(result dkim.Status, msg string, i int) *ArcResult {
		return &ArcResult{Result: dkim.Result{Status: result, Err: fmt.Errorf("i=%d %s", i, msg), Index: i}, Chain: chain}
	}

	// Validate results
	//
	//	"The "cv" value for all ARC-Seal header fields MUST NOT be
	//	"fail".  For ARC Sets with instance values > 1, the values
	//	MUST be "pass".  For the ARC Set with instance value = 1, the
	//	value MUST be "none"."
	for _, res := range chain {
		switch {
		case !res.ChainSigValid:
			return arcResult(dkim.StatusFail, fmt.Sprintf("%s did not validate", HEADER_FORWARD_SIG), res.Instance), nil
		case !res.ChainSealValid:
			return arcResult(dkim.StatusFail, fmt.Sprintf("%s did not validate", HEADER_FORWARD_SEAL), res.Instance), nil
		case res.CV == dkim.StatusFail:
			return arcResult(dkim.StatusFail, fmt.Sprintf("%s: cv failed", HEADER_FORWARD_SEAL), res.Instance), nil
		case (res.Instance == 1) && (res.CV != dkim.StatusNone):
			return arcResult(dkim.StatusFail, fmt.Sprintf("%s: cv should be none", HEADER_FORWARD_SEAL), res.Instance), nil
		case (res.Instance > 1) && (res.CV != dkim.StatusPass):
			return arcResult(dkim.StatusFail, fmt.Sprintf("%s: cv should pass", HEADER_FORWARD_SEAL), res.Instance), nil
		}
	}

	return &ArcResult{Result: dkim.Result{Status: dkim.StatusPass}, Chain: chain}, nil
}

func Forward(
	elog *slog.Logger, resolver dns.Resolver,
	domain dns.Domain, selectors []dkim.Selector,
	smtputf8 bool,
	bodybz []byte,
	mailfrom string, ipfrom string,
	from *mail.Address, to []*mail.Address, cc []*mail.Address, bcc []*mail.Address,
	subject string, timestamp time.Time, messageId string,
	ignoreTest bool, strictExpiration bool, now func() time.Time, rec *dkim.Record,
) ([]utils.Header, io.Reader, error) {
	// envelope sender or MAIL FROM address, is set by the email client or server initiating the SMTP transaction
	r := bytes.NewReader(bodybz)
	hdrsOriginal, bodyOffset, err := utils.ParseHeaders(bufio.NewReader(&moxio.AtReader{R: r}))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s", dkim.ErrHeaderMalformed, err)
	}
	r = bytes.NewReader(bodybz)
	rawBody, err := io.ReadAll(bufio.NewReader(&moxio.AtReader{R: r, Offset: int64(bodyOffset)}))
	if err != nil {
		return nil, nil, err
	}
	r = bytes.NewReader(bodybz)
	hdrsForward, err := BuildForwardHeaders(elog, smtputf8, r, hdrsOriginal, from, to, cc, bcc, subject, timestamp, messageId)
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
	dkimResults, err := dkim.Verify(elog, resolver, smtputf8, dkim.DKIMSpec.PolicySig, hdrsOriginal, bufio.NewReader(bytes.NewReader(rawBody)), true, ignoreTest, false, now, nil)
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

	// auth results header
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

	// forward signature header
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

	// forward chain seal header
	// fill in nil for dkim context, as it is not needed for signing the forward chain seal
	arcSets = append(arcSets, arc.ArcSet{Sigs: []*dkim.Sig{nil, sigsAuth[0], sigsMS[0]}, I: instance})
	prefixed := GetChainHeaders(arcSets, instance-1)

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

var DkimCtxSpec = dkim.Spec{
	HeaderName:   HEADER_FORWARD_DKIM_CTX,
	RequiredTags: []string{"i", HEADER_SUBJECT, HEADER_FROM, HEADER_TO, HEADER_MESSAGE_ID, HEADER_DATE, HEADER_DKIM_SIGNATURE},
	// optional: HEADER_CC, HEADER_BCC, HEADER_REPLY_TO, HEADER_REFERENCES, HEADER_IN_REPLY_TO
	HeaderCanonicalization: "relaxed",
	BodyCanonicalization:   "relaxed",
	PolicySig:              PolicyDkimCtx,
	PolicyHeader:           PolicyHeadersDkimCtx,
	PolicyParsing:          PolicyParsingDkimCtx,
	CheckSignatureParams:   CheckSignatureParamsDkimCtx,
	NewSigWithDefaults:     NewSigWithDefaultsDkimCtx,
	BuildSignatureHeader:   BuildHeaderDkimCtx,
	RequiredHeaders:        []dkim.HeaderInstance{},
	ParseSignature:         ParseSignatureDkimCtx,
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
	RequiredHeaders:        []dkim.HeaderInstance{},
}

var ForwardSignatureSpec = dkim.Spec{
	HeaderName:             HEADER_FORWARD_SIG,
	RequiredTags:           []string{"a", "b", "bh", "d", "h", "s", "i", FIELD_DNS_REGISTRY, FIELD_EMAIL_REGISTRY},
	HeaderCanonicalization: "relaxed",
	BodyCanonicalization:   "relaxed",
	PolicySig:              PolicyArcMS,
	PolicyHeader:           PolicyHeadersArcMS,
	PolicyParsing:          PolicyParsingArcMS,
	CheckSignatureParams:   CheckSignatureParamsArcMS,
	NewSigWithDefaults:     NewSigWithDefaultsArcMS,
	BuildSignatureHeader:   BuildHeaderMS,
	// ParseSignature:         ParseForwardSignature,
	// RequiredHeaders: append(dkim.BuildHeaderInstances(strings.Split("From,To,Cc,Bcc,Reply-To,References,In-Reply-To,Subject,Date,Message-ID,Content-Type", ",")), dkim.HeaderInstance{Name: HEADER_FORWARD_DKIM_CTX, Instance: true}), //, HEADER_FORWARD_DNS_REGISTRY, HEADER_FORWARD_EMAIL_REGISTRY),
	RequiredHeaders: []dkim.HeaderInstance{{Name: HEADER_FORWARD_DKIM_CTX, Instance: true}},
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

func NewSigWithDefaultsDkimCtx() *dkim.Sig {
	return &dkim.Sig{
		Canonicalization: "relaxed/relaxed",
		Length:           -1,
		SignTime:         -1,
		ExpireTime:       -1,
	}
}

func PolicyDkimCtx(sig *dkim.Sig) error {
	return nil
}

func PolicyHeadersDkimCtx(hdrs []utils.Header) error {
	return nil
}

func PolicyParsingDkimCtx(ds *dkim.Sig, p *dkim.Parser, fieldName string) (bool, error) {
	switch fieldName {
	case "i":
		ds.Instance = int32(p.XNumber(2))
		return true, nil
	}
	return false, nil
}

func CheckSignatureParamsDkimCtx(sig *dkim.Sig) error {
	return nil
}

func BuildHeaderDkimCtx(s *dkim.Sig) (string, error) {
	// expect added headers in .Tags
	w := &message.HeaderWriter{}
	w.Addf("", "%s: i=%d;", s.HeaderFull.Key, s.Instance)

	for _, tag := range s.Tags {
		for _, field := range tag {
			w.Addf(" ", "%s=%s;", field.Key, field.Value)
		}
	}

	w.Add("\r\n")
	return w.String(), nil
}

func ParseSignatureDkimCtx(
	header *utils.Header,
	smtputf8 bool,
	required []string,
	parsingPolicy func(ds *dkim.Sig, p *dkim.Parser, fieldName string) (bool, error),
	newSig func() *dkim.Sig,
) (sig *dkim.Sig, err error) {
	defer func() {
		if x := recover(); x != nil {
			if xerr, ok := x.(error); ok {
				sig = nil
				err = xerr
			} else {
				panic(x)
			}
		}
	}()

	buf := header.Raw
	if !bytes.HasSuffix(buf, []byte("\r\n")) {
		return nil, dkim.ErrSigMissingCRLF
	}
	buf = buf[:len(buf)-2]

	ds := newSig()
	ds.HeaderFull = header
	seen := map[string]struct{}{}
	p := dkim.NewParser(string(buf), smtputf8)

	// Parse field name
	name := p.XHdrName(false)
	if !strings.EqualFold(name, header.Key) {
		return nil, dkim.ErrSigHeader
	}
	p.Wsp()
	p.XTake(":")
	p.Wsp()

	// Parse semicolon-separated fields
	for !p.Empty() {
		p.Fws()

		// Skip empty “;” between folded lines
		for p.HasPrefix(";") {
			p.XTake(";")
			p.Fws()
		}
		if p.Empty() {
			break
		}

		// tagName := p.XTagName()
		tagName := p.DottedName(false) // Allows "Message-ID", "List-Unsubscribe", etc.
		p.Fws()
		p.XTake("=")
		p.Fws()

		// Special parsing for known types
		switch tagName {
		case "i":
			inst := int(p.XNumber(3))
			if inst <= 0 {
				return nil, fmt.Errorf("dkim: invalid instance i=%d", inst)
			}
			ds.Instance = int32(inst)
			seen["i"] = struct{}{}
		default:
			// Handle non-standard tags like Date, From, etc.
			value := p.XRawUntil(";")
			ds.Tags = append(ds.Tags, []dkim.Tag{{Key: tagName, Value: value}})
			seen[tagName] = struct{}{}
		}
	}

	// Check for required fields
	for _, req := range required {
		if _, ok := seen[req]; !ok {
			return nil, fmt.Errorf("%w: %q", dkim.ErrSigMissingTag, req)
		}
	}

	ds.VerifySig = []byte(p.GetTracked())
	return ds, nil
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
	messageId string,
) ([]utils.Header, error) {
	arcSets, err := arc.ExtractSignatureSets(hdrs, HEADER_NAMES, SPECS, smtputf8)
	if err != nil {
		return nil, err
	}
	instance := len(arcSets) + 1

	hdrs = BuildForwardHeadersInternal(elog, originalEmail, hdrs, from, to, cc, bcc, subjectAddl, timestamp, messageId, instance)
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
	newmessageId string,
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
		HEADER_DKIM_SIGNATURE,
	}

	messageId := ""
	dkimCtxParams := make(map[string]string, 0)
	hdrs2 := make([]utils.Header, 0)
	headers := make([]utils.Header, 0)

	for _, h := range hdrs {
		switch strings.ToLower(h.Key) {
		case HEADER_LOW_MESSAGE_ID:
			messageId = h.GetValueTrimmed() // with <>
			dkimCtxParams[HEADER_MESSAGE_ID] = messageId
			h = utils.Header{
				Key:   HEADER_MESSAGE_ID,
				Value: []byte(fmt.Sprintf(" <%s>\r\n", newmessageId)),
			}
			h.RebuildRaw()
		}
		hdrs2 = append(hdrs2, h)
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
			if _, ok := dkimCtxParams[h.Key]; !ok {
				dkimCtxParams[h.Key] = originalValue
				switch h.LKey {
				case HEADER_LOW_SUBJECT:
					dkimCtxParams[h.Key] = url.QueryEscape(dkimCtxParams[h.Key])
				case HEADER_LOW_DKIM_SIGNATURE:
					dkimCtxParams[h.Key] = base64.StdEncoding.EncodeToString([]byte(dkimCtxParams[h.Key]))
				}
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
		Key:   HEADER_FORWARD_DKIM_CTX,
		LKey:  strings.ToLower(HEADER_FORWARD_DKIM_CTX),
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

func VerifySignaturesBasic(elog *slog.Logger, resolver dns.Resolver, hdrs []utils.Header, rawBody []byte, headerNames []string, specs []dkim.Spec, smtputf8 bool, ignoreTest bool, now func() time.Time, rec *dkim.Record) (dkim.Status, [][]dkim.Result, error) {
	arcSets, err := arc.ExtractSignatureSets(hdrs, headerNames, specs, smtputf8)
	if err != nil {
		return dkim.StatusFail, nil, err
	}

	//	"The maximum number of ARC Sets that can be attached to a
	//	message is 50.  If more than the maximum number exist, the
	//	Chain Validation Status is "fail..."
	l := len(arcSets)
	switch {
	case l == 0:
		return dkim.StatusNone, nil, ErrMsgNotSigned
	case l > 50:
		return dkim.StatusFail, nil, ErrArcLimit
	}

	var results [][]dkim.Result
	for i, set := range arcSets {
		ress := make([]dkim.Result, 0)
		for x, sig := range set.Sigs {
			spec := specs[x]
			if x == ChainNdx {
				// arc seal
				spec.GetPrefixHeaders = func() []utils.Header { return GetChainHeaders(arcSets, i) }
			}
			res := dkim.VerifySignatureGeneric(elog, spec, resolver, smtputf8, hdrs, bufio.NewReader(bytes.NewReader(rawBody)), sig, ignoreTest, true, now, rec)
			ress = append(ress, res)
		}
		// rebuild previous email context needed for DKIM signature and forward signature
		origHeaders, err := RebuildDkim(ress[0].Sig.Tags, hdrs, set.I)
		if err != nil {
			return dkim.StatusFail, nil, err
		}

		// // process dkim context first, to reconstruct original headers
		// res := dkim.VerifySignatureGeneric(elog, specs[DkimCtxNdx], resolver, smtputf8, hdrs, bufio.NewReader(bytes.NewReader(rawBody)), set.Sigs[DkimCtxNdx], ignoreTest, true, now, rec)
		// ress = append(ress, res)

		// // rebuild previous email context needed for DKIM signature and forward signature
		// origHeaders, err := RebuildDkim(ress[0].Sig.Tags, hdrs, set.I)
		// if err != nil {
		// 	return dkim.StatusFail, nil, err
		// }

		// // auth results
		// res = dkim.VerifySignatureGeneric(elog, specs[AuthNdx], resolver, smtputf8, hdrs, bufio.NewReader(bytes.NewReader(rawBody)), set.Sigs[AuthNdx], ignoreTest, true, now, rec)
		// ress = append(ress, res)

		// // forward signature
		// res = dkim.VerifySignatureGeneric(elog, specs[SigNdx], resolver, smtputf8, hdrs, bufio.NewReader(bytes.NewReader(rawBody)), set.Sigs[SigNdx], ignoreTest, true, now, rec)
		// ress = append(ress, res)

		// // chain seal signature
		// spec := specs[ChainNdx]
		// spec.GetPrefixHeaders = func() []utils.Header { return GetChainHeaders(arcSets, i) }
		// res = dkim.VerifySignatureGeneric(elog, spec, resolver, smtputf8, hdrs, bufio.NewReader(bytes.NewReader(rawBody)), set.Sigs[ChainNdx], ignoreTest, true, now, rec)
		// ress = append(ress, res)

		// previous email's original DKIM signature
		resp, err := dkim.Verify(elog, resolver, smtputf8, dkim.DKIMSpec.PolicySig, origHeaders, bufio.NewReader(bytes.NewReader(rawBody)), true, ignoreTest, false, now, nil)
		if err != nil {
			return dkim.StatusFail, nil, err
		}
		ress = append(ress, resp[0])

		results = append(results, ress)
	}

	return dkim.StatusPass, results, nil
}

func RebuildDkim(tags [][]dkim.Tag, hdrs []utils.Header, instance int) ([]utils.Header, error) {
	vals := map[string]string{}
	var err error

	// Extract all original header values from DKIM context tags
	for _, tag := range tags {
		for _, t := range tag {
			k := strings.ToLower(t.Key)
			vals[k] = t.Value
			switch k {
			case HEADER_LOW_SUBJECT:
				vals[k], err = url.QueryUnescape(vals[k])
				if err != nil {
					return nil, err
				}
			case HEADER_LOW_DKIM_SIGNATURE:
				v, err := base64.StdEncoding.DecodeString(vals[k])
				if err != nil {
					return nil, err
				}
				vals[k] = string(v)
			}
			// add initial space
			vals[k] = " " + vals[k]
			// add end of line for headers
			vals[k] += utils.CRLF
		}
	}

	// Find the index of the first Provable-Forward-* header with the given instance
	cutoffIndex := len(hdrs) // Default to keeping all headers if no forward headers found
	for i := len(hdrs) - 1; i >= 0; i-- {
		h := hdrs[i]
		if strings.HasPrefix(h.Key, HEADER_FORWARD_PREFIX) {
			headerInstance := extractInstanceFromHeader(h)
			if headerInstance == instance {
				cutoffIndex = i + 1
				break
			}
		}
	}
	if cutoffIndex < 0 {
		return nil, fmt.Errorf("provable- header cannot be first")
	}

	// Keep headers up to the cutoff index
	newlen := len(hdrs) - cutoffIndex
	rebuiltHeaders := make([]utils.Header, newlen)
	copy(rebuiltHeaders, hdrs[cutoffIndex:])

	added := map[string]bool{}
	// Replace header values with original values from DKIM context tags
	for i, h := range rebuiltHeaders {
		if val, ok := vals[h.LKey]; ok {
			rebuiltHeaders[i].Value = []byte(val)
			rebuiltHeaders[i].RebuildRaw()
			added[h.LKey] = true
		}
	}

	// add original tags that are missing
	for _, tag := range tags {
		for _, t := range tag {
			k := strings.ToLower(t.Key)
			if _, ok := added[k]; !ok {
				value := vals[k]
				h := utils.Header{
					Key:   t.Key,
					LKey:  k,
					Value: []byte(value),
				}
				h.RebuildRaw()
				rebuiltHeaders = append([]utils.Header{h}, rebuiltHeaders...)
			}
		}
	}

	// // Add the original DKIM signature header if available
	// if dkimSig, ok := vals[HEADER_LOW_DKIM_SIGNATURE]; ok && !replacedDKIM {
	// 	dkimHeader := utils.Header{
	// 		Key:   HEADER_DKIM_SIGNATURE,
	// 		LKey:  HEADER_LOW_DKIM_SIGNATURE,
	// 		Value: []byte(dkimSig),
	// 	}
	// 	dkimHeader.RebuildRaw()
	// 	rebuiltHeaders = append([]utils.Header{dkimHeader}, rebuiltHeaders...)
	// }

	return rebuiltHeaders, nil
}

// Helper function to extract instance number from Provable-Forward-* headers
func extractInstanceFromHeader(h utils.Header) int {
	// Parse the header value to extract i= parameter
	value := strings.TrimSpace(string(h.Value))
	if strings.HasPrefix(value, "i=") {
		parts := strings.Split(value, ";")
		if len(parts) > 0 {
			iPart := strings.TrimSpace(parts[0])
			if strings.HasPrefix(iPart, "i=") {
				if instance, err := strconv.Atoi(iPart[2:]); err == nil {
					return instance
				}
			}
		}
	}
	return 0
}

func GetChainHeaders(arcSets []arc.ArcSet, index int) []utils.Header {
	var res []utils.Header
	for _, arcSet := range arcSets {
		res = append(res,
			*arcSet.Sigs[AuthNdx].HeaderFull, // authResults
			*arcSet.Sigs[SigNdx].HeaderFull,  // message signature
		)

		if arcSet.Sigs[SigNdx].Instance == int32(index+1) {
			break
		}
		// skip last seal as it's not in the signature
		res = append(res, *arcSet.Sigs[ChainNdx].HeaderFull)
	}
	return res
}
