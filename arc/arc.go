package arc

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

	"github.com/loredanacirstea/mailverif/dkim"
	"github.com/loredanacirstea/mailverif/dmarc"
	"github.com/loredanacirstea/mailverif/dns"
	message "github.com/loredanacirstea/mailverif/utils"
	moxio "github.com/loredanacirstea/mailverif/utils"
	smtp "github.com/loredanacirstea/mailverif/utils"
	utils "github.com/loredanacirstea/mailverif/utils"
)

const (
	ARC_SEAL_HEADER = "ARC-Seal"
	ARC_MS_HEADER   = "ARC-Message-Signature"
	ARC_AUTH_HEADER = "ARC-Authentication-Results"
)

var (
	ARC_SEAL_HEADER_LOWER = strings.ToLower(ARC_SEAL_HEADER)
	ARC_MS_HEADER_LOWER   = strings.ToLower(ARC_MS_HEADER)
	ARC_AUTH_HEADER_LOWER = strings.ToLower(ARC_AUTH_HEADER)
)

var (
	ErrMissingArcFields      = errors.New("missing arc fields")
	ErrInstanceMismatch      = errors.New("mismatch of arc header instances")
	ErrArcLimit              = errors.New("message over arc-set limit")
	ErrMsgNotSigned          = errors.New("message is not arc signed")
	ErrAMSValidationFailure  = errors.New("most recent ARC-Message-Signature did not validate")
	ErrAMSIncludesSealHeader = errors.New("Arc-Message-Signature MUST NOT sign ARC-Seal")
)

type ArcResult struct {
	// Final result of verification
	Result dkim.Result

	// Result data at each part of the chain until failure
	Chain []ArcSetResult `json:"chain"`
}

// ArcSetResult holds the result data for verification of a single arc set
type ArcSetResult struct {
	Instance int         `json:"instance"`
	Spf      dkim.Status `json:"spf"`
	Dkim     dkim.Status `json:"dkim"`
	Dmarc    dkim.Status `json:"dmarc"`
	AMSValid bool        `json:"ams-vaild"`
	ASValid  bool        `json:"as-valid"`
	CV       dkim.Status `json:"cv"`
}

type ArcSet struct {
	Sigs []*dkim.Sig
	I    int
}

var (
	HEADER_NAMES = []string{ARC_AUTH_HEADER, ARC_MS_HEADER, ARC_SEAL_HEADER}
	SPECS        = []dkim.Spec{AuthResultsSpec, ArcMessageSignatureSpec, ArcSealSpec}
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

	status, results, err := VerifySignaturesBasic(elog, resolver, hdrs, bufio.NewReader(bytes.NewReader(rawBody)), HEADER_NAMES, SPECS, smtputf8, ignoreTest, now, rec)
	if err != nil {
		return &ArcResult{Result: dkim.Result{Status: status, Err: err}}, nil
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
		res.AMSValid = ress[1].Status == dkim.StatusPass
		res.ASValid = ress[2].Status == dkim.StatusPass
		chain = append(chain, res)
	}

	arcResult := func(result dkim.Status, msg string, i int) *ArcResult {
		return &ArcResult{Result: dkim.Result{Status: result, Err: fmt.Errorf("i=%d %s", i, msg), Index: i}, Chain: chain}
	}

	if !chain[0].AMSValid {
		return arcResult(dkim.StatusFail, "Most recent ARC-Message-Signature did not validate", chain[0].Instance), nil
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
		case !res.ASValid:
			return arcResult(dkim.StatusFail, "ARC-Seal did not validate", res.Instance), nil
		case (res.Instance == 1) && (res.CV != dkim.StatusNone):
			return arcResult(dkim.StatusFail, "ARC-Seal reported invalid status", res.Instance), nil
		case (res.Instance > 1) && (res.CV != dkim.StatusPass):
			return arcResult(dkim.StatusFail, "ARC-Seal reported invalid status", res.Instance), nil
		}
	}

	return &ArcResult{Result: dkim.Result{Status: dkim.StatusPass}, Chain: chain}, nil
}

func Sign(elog *slog.Logger, resolver dns.Resolver, local smtp.Localpart, domain dns.Domain, selectors []dkim.Selector, smtputf8 bool, msg io.ReaderAt, mailfrom string, ipfrom string, mailServerDomain string, ignoreTest bool, strictExpiration bool, now func() time.Time, rec *dkim.Record) ([]utils.Header, error) {
	// envelope sender or MAIL FROM address, is set by the email client or server initiating the SMTP transaction
	hdrs, bodyOffset, err := utils.ParseHeaders(bufio.NewReader(&moxio.AtReader{R: msg}))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", dkim.ErrHeaderMalformed, err)
	}
	rawBody, err := io.ReadAll(bufio.NewReader(&moxio.AtReader{R: msg, Offset: int64(bodyOffset)}))
	if err != nil {
		return nil, err
	}

	if len(hdrs) == 0 {
		return nil, fmt.Errorf("no headers")
	}

	arcSets, err := ExtractSignatureSets(hdrs, HEADER_NAMES, SPECS, smtputf8)
	if err != nil {
		return nil, err
	}
	instance := len(arcSets) + 1

	signedHeaders := []utils.Header{}

	_selectors := make([]dkim.Selector, len(selectors))
	copy(_selectors, selectors)

	// dkim checks
	dkimResults, err := dkim.Verify(elog, resolver, smtputf8, dkim.DKIMSpec.PolicySig, hdrs, bufio.NewReader(bytes.NewReader(rawBody)), ignoreTest, strictExpiration, now, rec)
	if err != nil {
		return nil, err
	}

	// auth checks
	from, err := GetFrom(hdrs)
	if err != nil {
		return nil, err
	}
	headerFrom := strings.Split(from.Address, "@")[1]
	spfRes, dmarcPass, cv := BuildAuthResults(from, mailfrom, ipfrom, dkimResults, instance, resolver)

	sigsAuth, err := dkim.BuildSignatureGeneric(elog, AuthResultsSpec, hdrs, bufio.NewReader(bytes.NewReader(rawBody)), domain, _selectors, smtputf8, now)
	if err != nil {
		return nil, err
	}
	sigsAuth[0].Instance = int32(instance)
	tags := BuildAuthenticationResultTags(mailServerDomain, mailfrom, headerFrom, dkimResults, spfRes, dmarcPass)
	sigsAuth[0].Tags = tags

	headers, err := dkim.SignGeneric(AuthResultsSpec, sigsAuth, hdrs, nil)
	if err != nil {
		return nil, err
	}
	sigsAuth[0].HeaderFull.Raw = headers[0].Raw
	signedHeaders = append(signedHeaders, headers...)

	_selectors = make([]dkim.Selector, len(selectors))
	copy(_selectors, selectors)
	sigsMS, err := dkim.BuildSignatureGeneric(elog, ArcMessageSignatureSpec, hdrs, bufio.NewReader(bytes.NewReader(rawBody)), domain, _selectors, smtputf8, now)
	if err != nil {
		return nil, err
	}
	sigsMS[0].Instance = int32(instance)
	headers, err = dkim.SignGeneric(ArcMessageSignatureSpec, sigsMS, hdrs, nil)
	if err != nil {
		return nil, err
	}
	sigsMS[0].HeaderFull.Raw = headers[0].Raw
	signedHeaders = append(signedHeaders, headers...)

	// seal
	arcSets = append(arcSets, ArcSet{Sigs: []*dkim.Sig{sigsAuth[0], sigsMS[0]}, I: instance})
	prefixed := GetChainHeaders(arcSets, instance-1)

	_selectors = make([]dkim.Selector, len(selectors))
	copy(_selectors, selectors)
	sigsAS, err := dkim.BuildSignatureGeneric(elog, ArcSealSpec, hdrs, bufio.NewReader(bytes.NewReader(rawBody)), domain, _selectors, smtputf8, now)
	if err != nil {
		return nil, err
	}
	sigsAS[0].Instance = int32(instance)
	sigsAS[0].Tags = [][]dkim.Tag{{{Key: "cv", Value: cv}}}
	headers, err = dkim.SignGeneric(ArcSealSpec, sigsAS, hdrs, prefixed)
	if err != nil {
		return nil, err
	}
	signedHeaders = append(signedHeaders, headers...)
	return signedHeaders, nil
}

var ArcSealSpec = dkim.Spec{
	HeaderName:             ARC_SEAL_HEADER,
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

var ArcMessageSignatureSpec = dkim.Spec{
	HeaderName:             ARC_MS_HEADER,
	RequiredTags:           []string{"a", "b", "bh", "d", "h", "s", "i"},
	HeaderCanonicalization: "relaxed",
	BodyCanonicalization:   "relaxed",
	PolicySig:              PolicyArcMS,
	PolicyHeader:           PolicyHeadersArcMS,
	PolicyParsing:          PolicyParsingArcMS,
	CheckSignatureParams:   CheckSignatureParamsArcMS,
	NewSigWithDefaults:     NewSigWithDefaultsArcMS,
	BuildSignatureHeader:   BuildHeaderMS,
	RequiredHeaders:        strings.Split("From,To,Cc,Bcc,Reply-To,References,In-Reply-To,Subject,Date,Message-ID,Content-Type", ","),
}

var AuthResultsSpec = dkim.Spec{
	HeaderName:             ARC_AUTH_HEADER,
	RequiredTags:           []string{"i"},
	HeaderCanonicalization: "relaxed",
	BodyCanonicalization:   "relaxed",
	PolicySig:              PolicyArcAuth,
	PolicyHeader:           PolicyHeadersArcAuth,
	PolicyParsing:          PolicyParsingArcAuth,
	CheckSignatureParams:   CheckSignatureParamsArcAuth,
	NewSigWithDefaults:     NewSigWithDefaultsArcAuth,
	ParseSignature:         ParseSignatureAuthResults,
	BuildSignatureHeader:   BuildHeaderAuth,
	RequiredHeaders:        []string{},
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
	}
	return false, nil
}

func CheckSignatureParamsArcMS(sig *dkim.Sig) error {
	for _, h := range sig.SignedHeaders {
		if strings.ToLower(h) == ARC_SEAL_HEADER_LOWER {
			return ErrAMSIncludesSealHeader
		}
	}
	return nil
}

func NewSigWithDefaultsArcAuth() *dkim.Sig {
	return &dkim.Sig{
		Canonicalization: "relaxed/relaxed",
		Length:           -1,
		SignTime:         -1,
		ExpireTime:       -1,
		Tags:             [][]dkim.Tag{},
	}
}

func PolicyArcAuth(sig *dkim.Sig) error {
	return nil
}

func PolicyHeadersArcAuth(hdrs []utils.Header) error {
	return nil
}

func PolicyParsingArcAuth(ds *dkim.Sig, p *dkim.Parser, fieldName string) (bool, error) {
	switch fieldName {
	case "i":
		ds.Instance = int32(p.XNumber(2))
		return true, nil
	}
	return false, nil
}

func CheckSignatureParamsArcAuth(sig *dkim.Sig) error {
	return nil
}

// Returns all the arc headers up until 'instance', in the correct order.
// Headers are used to produce arc-seal signature.
// https://www.rfc-editor.org/rfc/rfc8617.html#section-5.1.1
func GetChainHeaders(arcSets []ArcSet, i int) []utils.Header {
	var res []utils.Header
	for _, arcSet := range arcSets {
		res = append(res,
			*arcSet.Sigs[0].HeaderFull, // authResults
			*arcSet.Sigs[1].HeaderFull, // message signature
		)

		if arcSet.Sigs[1].Instance == int32(i+1) {
			break
		}
		// skip last seal as it's not in the signature
		res = append(res, *arcSet.Sigs[2].HeaderFull)
	}
	return res
}

func VerifySignaturesBasic(elog *slog.Logger, resolver dns.Resolver, hdrs []utils.Header, bodyReader io.Reader, headerNames []string, specs []dkim.Spec, smtputf8 bool, ignoreTest bool, now func() time.Time, rec *dkim.Record) (dkim.Status, [][]dkim.Result, error) {
	arcSets, err := ExtractSignatureSets(hdrs, headerNames, specs, smtputf8)
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
			if x == 2 {
				// arc seal
				spec.GetPrefixHeaders = func() []utils.Header { return GetChainHeaders(arcSets, i) }
			}
			res := dkim.VerifySignatureGeneric(elog, spec, resolver, smtputf8, hdrs, bodyReader, sig, ignoreTest, true, now, rec)
			ress = append(ress, res)
		}
		results = append(results, ress)
	}
	return dkim.StatusPass, results, nil
}

func ExtractSignatureSets(headers []utils.Header, headerNames []string, spec []dkim.Spec, smtputf8 bool) ([]ArcSet, error) {
	specMap := map[string]dkim.Spec{}
	for i, h := range headerNames {
		headerNames[i] = strings.ToLower(h)
		specMap[headerNames[i]] = spec[i]
	}
	sets := make([]ArcSet, 0)
	instance := 1
	hl := len(headerNames)

	// iterate bottom -> top, we expect instance number to start from 1 and increment
	reverseH := append([]utils.Header(nil), headers...)
	slices.Reverse(reverseH)
	for _, h := range reverseH {
		spec, ok := specMap[h.LKey]
		if !ok {
			continue
		}
		parseSig := spec.ParseSignature
		if parseSig == nil {
			parseSig = dkim.ParseSignature
		}
		sig, err := parseSig(&h, smtputf8, spec.RequiredTags, spec.PolicyParsing, spec.NewSigWithDefaults)
		if err != nil {
			return nil, err
		}
		if sig.Instance != int32(instance) {
			return nil, fmt.Errorf("signature set instance mismatch, expected i=%d, got i=%d", instance, sig.Instance)
		}
		l := len(sets)
		index := instance - 1
		if instance > l {
			sets = append(sets, ArcSet{I: instance, Sigs: make([]*dkim.Sig, hl)})
		}
		x := slices.Index(headerNames, sig.HeaderFull.LKey)

		sets[index].Sigs[x] = sig
		if x+1 == hl {
			for _, s := range sets[index].Sigs {
				if s == nil {
					return nil, ErrMissingArcFields
				}
			}
			instance += 1
		}
	}
	return sets, nil
}

func ParseSignatureAuthResults(
	header *utils.Header,
	smtputf8 bool,
	required []string,
	parsingPolicy func(ds *dkim.Sig, p *dkim.Parser, fieldName string) (bool, error),
	newSig func() *dkim.Sig,
) (sig *dkim.Sig, err error) {
	defer func() {
		if x := recover(); x == nil {
			return
		} else if xerr, ok := x.(error); ok {
			sig = nil
			err = xerr
		} else {
			panic(x)
		}
	}()
	buf := header.Raw

	xerrorf := func(format string, args ...any) {
		panic(fmt.Errorf(format, args...))
	}

	if !bytes.HasSuffix(buf, []byte("\r\n")) {
		xerrorf("%w", dkim.ErrSigMissingCRLF)
	}
	buf = buf[:len(buf)-2]

	ds := newSig()
	ds.HeaderFull = header
	seen := map[string]struct{}{}
	p := dkim.NewParser(string(buf), smtputf8)
	name := p.XHdrName(false)
	if !strings.EqualFold(name, header.Key) {
		xerrorf("%w", dkim.ErrSigHeader)
	}
	p.Wsp()
	p.XTake(":")
	p.Wsp()

	// --- mandatory “i=<instance>” tag ---------------------------------------
	if !p.HasPrefix("i") {
		return nil, fmt.Errorf("%w: missing i= tag", dkim.ErrSigMissingTag)
	}
	p.XTake("i")
	p.Fws()
	p.XTake("=")
	inst := int(p.XNumber(3)) // <3 digits is plenty (spec only allows 1-50)
	if inst <= 0 {
		return nil, fmt.Errorf("arc-auth-results: invalid instance %d", inst)
	}
	seen["i"] = struct{}{}
	ds.Instance = int32(inst)

	// Semicolon separator
	p.Fws()
	p.XTake(";")
	p.Fws()

	// --- authserv-id (token WITHOUT “=”) ------------------------------------
	authServID := p.XTakeFn1(false, func(c rune, _ int) bool { return c != ';' })
	authServID = strings.TrimSpace(authServID)

	// Consume optional “;” after authserv-id, leave the remainder verbatim.
	if p.Peekfws(";") {
		p.Fws()
		p.XTake(";")
	}

	// {
	// 	dkim:"neutral"
	// 	message:"(no key)"
	// 	"header.i":"@mail.provable.dev"
	// 	"header.s":"2024a"
	// }

	results, perr := parseAuthResultSetsFromParser(&p)
	if perr != nil {
		return nil, perr
	}

	seen["authserv-id"] = struct{}{}
	ds.Tags = append(ds.Tags, []dkim.Tag{{Key: "authserv-id", Value: authServID}})
	ds.Tags = append(ds.Tags, results...)

	// ../rfc/6376:2532
	for _, req := range required {
		if _, ok := seen[req]; !ok {
			xerrorf("%w: %q", dkim.ErrSigMissingTag, req)
		}
	}

	ds.VerifySig = []byte(p.GetTracked())
	return ds, nil
}

// parseAuthResultSetsFromParser consumes everything that follows the
// “authserv-id;” part of an ARC-Authentication-Results header and turns it into
// a slice of maps, one map per auth-result clause.
//
// It relies *exclusively* on the generic DKIM Parser so we get identical FWS
// handling and error semantics.
func parseAuthResultSetsFromParser(p *dkim.Parser) ([][]dkim.Tag, error) {
	var sets [][]dkim.Tag

loopClauses:
	for {
		p.Fws() // eat any leading FWS

		// Skip empty “;” between folded lines
		for !p.Empty() && p.HasPrefix(";") {
			p.XTake(";")
			p.Fws()
		}
		if p.Empty() {
			break // nothing more
		}

		clause := make([]dkim.Tag, 0)

		// <method>=<result>
		method := strings.ToLower(p.StatusValue()) // XHyphenatedWord
		p.Fws()
		p.XTake("=")
		p.Fws()

		// result token (pass / fail / neutral / none …)
		// StatusValue XHyphenatedWord
		res := strings.ToLower(p.StatusValue())
		clause = append(clause, dkim.Tag{Key: method, Value: res})
		p.Fws()

		// optional comment:  “( … )”
		if p.HasPrefix("(") {
			p.XTake("(")
			var msg strings.Builder
			for !p.Empty() && !p.HasPrefix(")") {
				msg.WriteRune(p.XChar())
			}
			p.XTake(")")
			clause = append(clause, dkim.Tag{Key: "message", Value: "(" + msg.String() + ")"})
			p.Fws()
		}

		// zero or more <key>=<value> pairs until we hit “;” or end-of-header
		for !p.Empty() && !p.HasPrefix(";") {
			// key := p.XHdrName(false)
			key := p.DottedName(false)
			p.Fws()
			p.XTake("=")
			p.Fws()

			// value: read until whitespace or semicolon
			var val strings.Builder
			for !p.Empty() && !(p.HasPrefix(";") || p.HasPrefix(" ") || p.HasPrefix("\t")) {
				val.WriteRune(p.XChar())
			}
			clause = append(clause, dkim.Tag{Key: key, Value: val.String()})
			p.Fws()
		}

		sets = append(sets, clause)

		// another clause follows?
		if p.Peekfws(";") {
			p.Fws()
			p.XTake(";")
			continue loopClauses
		}
		break
	}
	return sets, nil
}

func buildAuthResult(v []dkim.Tag) string {
	val := ""
	for _, v := range v {
		if v.Key == "message" {
			val += " " + v.Value
			break
		}
		val += " " + v.Key + "=" + v.Value
	}
	return val
}

func BuildHeaderAuth(s *dkim.Sig) (string, error) {
	authServID := ""
	results := []string{}
Outer:
	for _, t := range s.Tags {
		for _, v := range t {
			if v.Key == "authserv-id" {
				authServID = v.Value
				continue Outer
			}
		}
		results = append(results, buildAuthResult(t))
	}

	w := &message.HeaderWriter{}
	w.Addf("", "%s: i=%d; %s;", s.HeaderFull.Key, s.Instance, authServID)
	w.Addf("", "%s", strings.Join(results, ";"))
	w.Add("\r\n")
	return w.String(), nil
}

func BuildHeaderMS(s *dkim.Sig) (string, error) {
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
	s.BuildSignature(w)

	w.Add("\r\n")
	return w.String(), nil
}

func BuildHeaderAS(s *dkim.Sig) (string, error) {
	cv := ""
Outer:
	for _, t := range s.Tags {
		for _, v := range t {
			if v.Key == "cv" {
				cv = v.Value
				continue Outer
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

func GetFrom(hdrs []utils.Header) (*mail.Address, error) {
	for _, h := range hdrs {
		if h.LKey == "from" {
			return mail.ParseAddress(strings.Trim(string(h.Value), " \n\r"))
		}
	}
	return nil, fmt.Errorf("missing From header")
}

func BuildAuthResults(from *mail.Address, mailfrom string, ipfrom string, dkimResults []dkim.Result, instance int, resolver dns.Resolver) (spfRes dmarc.AuthResult, dmarcPass bool, cv string) {
	var err error
	mailfromDomain := strings.Split(mailfrom, "@")[1]
	headerFrom := strings.Split(from.Address, "@")[1]

	// Mark the DKIM result as pass if at least one signature passes
	// and aligns with the From domain (or satisfies relaxed alignment for DMARC).
	dkimpass := false
	dkimRes := make([]dmarc.AuthResult, len(dkimResults))
	for i, v := range dkimResults {
		dkimRes[i] = dmarc.AuthResult{Domain: v.Sig.Domain.String(), Valid: v.Err == nil}
		if v.Err == nil {
			dkimpass = true
		}
	}

	spfRes, err = dmarc.CheckSPF(mailfromDomain, ipfrom, resolver.LookupTXT)
	if err != nil {
		fmt.Println("SPF failed:", err)
		spfRes.Valid = false
	}

	// run dmarc tests on domain from header "From"
	dmarcPass = false
	dmarcRecord, err := dmarc.LookupWithOptions(headerFrom, resolver.LookupTXT)
	if err != nil {
		fmt.Println("DMARC failed:", err)
		dmarcPass = false
	} else {
		dmarcPass, dkimpass = dmarc.CheckDMARC(headerFrom, dmarcRecord, spfRes, dkimRes, dkimpass)
	}

	cv = "none"
	if instance > 1 {
		if dmarcPass && spfRes.Valid && dkimpass {
			cv = "pass"
		} else {
			cv = "fail"
		}
	}
	return spfRes, dmarcPass, cv
}

func BuildAuthenticationResultTags(mailServerDomain string, mailfrom string, headerFrom string, dkimResults []dkim.Result, spfRes dmarc.AuthResult, dmarcPass bool) [][]dkim.Tag {
	tags := [][]dkim.Tag{}
	tags = append(tags, []dkim.Tag{{Key: "authserv-id", Value: mailServerDomain}})

	for _, v := range dkimResults {
		tag := []dkim.Tag{
			{Key: "dkim", Value: string(v.Status)},
			{Key: "header.d", Value: v.Sig.Domain.String()},
		}
		tags = append(tags, tag)
	}

	spfStatus := dkim.StatusFail
	if spfRes.Valid {
		spfStatus = dkim.StatusPass
	}
	tag := []dkim.Tag{
		{Key: "spf", Value: string(spfStatus)},
		{Key: "smtp.mailfrom", Value: mailfrom},
	}
	tags = append(tags, tag)

	dmarcStatus := dkim.StatusFail
	if dmarcPass {
		dmarcStatus = dkim.StatusPass
	}
	tag = []dkim.Tag{
		{Key: "dmarc", Value: string(dmarcStatus)},
		{Key: "header.from", Value: headerFrom},
	}
	tags = append(tags, tag)
	return tags
}
