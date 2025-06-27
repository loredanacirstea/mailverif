package arc

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/loredanacirstea/mailverif/dkim"
	"github.com/loredanacirstea/mailverif/dns"
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

type arcResult struct {
	instance int
	amsValid bool
	asValid  bool
	cv       dkim.Status
}

type arcSet struct {
	sigs []*dkim.Sig
	i    int
}

func Verify(elog *slog.Logger, resolver dns.Resolver, smtputf8 bool, r io.ReaderAt, ignoreTest, strictExpiration bool, now func() time.Time, rec *dkim.Record) (*ArcResult, error) {
	headerNames := []string{ARC_AUTH_HEADER, ARC_MS_HEADER, ARC_SEAL_HEADER}
	specs := []dkim.Spec{AuthResultsSpec, ArcMessageSignatureSpec, ArcSealSpec}

	hdrs, bodyOffset, err := utils.ParseHeaders(bufio.NewReader(&moxio.AtReader{R: r}))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", dkim.ErrHeaderMalformed, err)
	}

	if len(hdrs) == 0 {
		return &ArcResult{Result: dkim.Result{Status: dkim.StatusNone}}, nil
	}

	status, results, err := VerifySignaturesBasic(elog, resolver, hdrs, bodyOffset, headerNames, specs, smtputf8, r, ignoreTest, now, rec)
	if err != nil {
		return &ArcResult{Result: dkim.Result{Status: status, Err: err}}, nil
	}

	chain := []ArcSetResult{}

	// check auth results
	for _, ress := range results {
		res := ArcSetResult{Instance: int(ress[0].Sig.Instance)}
		for _, v := range ress[0].Sig.Tags {
			for key, value := range v {
				v := dkim.Status(value)
				switch key {
				case "dkim":
					if string(res.Dkim) == "" || v == dkim.StatusPass {
						res.Dkim = v
					}
				case "dmarc":
					res.Dmarc = v
				case "spf":
					res.Spf = v
				}
			}
		}
		for _, v := range ress[2].Sig.Tags {
			for key, value := range v {
				v := dkim.Status(value)
				switch key {
				case "cv":
					res.CV = v
				}
			}
		}
		res.AMSValid = ress[1].Status == dkim.StatusPass
		res.ASValid = ress[2].Status == dkim.StatusPass
		chain = append(chain, res)
	}

	arcResult := func(result dkim.Status, msg string, i int) *ArcResult {
		return &ArcResult{Result: dkim.Result{Status: dkim.StatusFail, Err: fmt.Errorf("i=%d %s", i, msg), Index: i}, Chain: chain}
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

// Sign returns line(s) with DKIM-Signature headers, generated according to the configuration.
func Sign(elog *slog.Logger, local smtp.Localpart, domain dns.Domain, selectors []dkim.Selector, smtputf8 bool, msg io.ReaderAt, now func() time.Time) ([]string, error) {
	// hdrs, bodyOffset, err := utils.ParseHeaders(bufio.NewReader(&moxio.AtReader{R: msg}))
	// if err != nil {
	// 	return nil, fmt.Errorf("%w: %s", dkim.ErrHeaderMalformed, err)
	// }
	return nil, nil
}

var ArcSealSpec = dkim.Spec{
	HeaderName:           ARC_SEAL_HEADER,
	RequiredTags:         []string{"a", "b", "d", "s", "i", "cv"},
	CanonicalizationDef:  "relaxed/relaxed",
	PolicySig:            PolicyArcSeal,
	PolicyHeader:         PolicyHeadersArcSeal,
	PolicyParsing:        PolicyParsingArcSeal,
	CheckSignatureParams: CheckSignatureParamsArcSeal,
	NewSigWithDefaults:   NewSigWithDefaultsArcSeal,
}

var ArcMessageSignatureSpec = dkim.Spec{
	HeaderName:           ARC_MS_HEADER,
	RequiredTags:         []string{"a", "b", "bh", "d", "h", "s", "i"},
	CanonicalizationDef:  "relaxed/relaxed",
	PolicySig:            PolicyArcMS,
	PolicyHeader:         PolicyHeadersArcMS,
	PolicyParsing:        PolicyParsingArcMS,
	CheckSignatureParams: CheckSignatureParamsArcMS,
	NewSigWithDefaults:   NewSigWithDefaultsArcMS,
}

var AuthResultsSpec = dkim.Spec{
	HeaderName:           ARC_AUTH_HEADER,
	RequiredTags:         []string{"i"},
	CanonicalizationDef:  "relaxed/relaxed",
	PolicySig:            PolicyArcAuth,
	PolicyHeader:         PolicyHeadersArcAuth,
	PolicyParsing:        PolicyParsingArcAuth,
	CheckSignatureParams: CheckSignatureParamsArcAuth,
	NewSigWithDefaults:   NewSigWithDefaultsArcAuth,
	ParseSignature:       ParseSignatureAuthResults,
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
		Tags:             make([]map[string]string, 0),
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
func getChainHeaders(arcSets []arcSet, i int) []utils.Header {
	var res []utils.Header
	for _, arcSet := range arcSets {
		res = append(res,
			*arcSet.sigs[0].HeaderFull, // authResults
			*arcSet.sigs[1].HeaderFull, // message signature
		)

		if arcSet.sigs[1].Instance == int32(i+1) {
			break
		}
		// skip last seal as it's not in the signature
		res = append(res, *arcSet.sigs[2].HeaderFull)
	}
	return res
}

func VerifySignaturesBasic(elog *slog.Logger, resolver dns.Resolver, hdrs []utils.Header, bodyOffset int, headerNames []string, specs []dkim.Spec, smtputf8 bool, r io.ReaderAt, ignoreTest bool, now func() time.Time, rec *dkim.Record) (dkim.Status, [][]dkim.Result, error) {
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
		for x, sig := range set.sigs {
			spec := specs[x]
			if x == 2 {
				// arc seal
				spec.GetPrefixHeaders = func() []utils.Header { return getChainHeaders(arcSets, i) }
			}
			res := dkim.VerifySignatureGeneric(elog, spec, resolver, smtputf8, hdrs, sig, bodyOffset, r, ignoreTest, true, now, rec)
			ress = append(ress, res)
		}
		results = append(results, ress)
	}
	return dkim.StatusPass, results, nil
}

func ExtractSignatureSets(headers []utils.Header, headerNames []string, spec []dkim.Spec, smtputf8 bool) ([]arcSet, error) {
	specMap := map[string]dkim.Spec{}
	for i, h := range headerNames {
		headerNames[i] = strings.ToLower(h)
		specMap[headerNames[i]] = spec[i]
	}
	sets := make([]arcSet, 0)
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
			sets = append(sets, arcSet{i: instance, sigs: make([]*dkim.Sig, hl)})
		}
		x := slices.Index(headerNames, sig.HeaderFull.LKey)

		sets[index].sigs[x] = sig
		if x+1 == hl {
			for _, s := range sets[index].sigs {
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
	ds.Tags = append(ds.Tags, map[string]string{"authserv-id": authServID})
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
func parseAuthResultSetsFromParser(p *dkim.Parser) ([]map[string]string, error) {
	var sets []map[string]string

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

		clause := make(map[string]string)

		// <method>=<result>
		method := strings.ToLower(p.StatusValue()) // XHyphenatedWord
		p.Fws()
		p.XTake("=")
		p.Fws()

		// result token (pass / fail / neutral / none …)
		// StatusValue XHyphenatedWord
		res := strings.ToLower(p.StatusValue())
		clause[method] = res
		p.Fws()

		// optional comment:  “( … )”
		if p.HasPrefix("(") {
			p.XTake("(")
			var msg strings.Builder
			for !p.Empty() && !p.HasPrefix(")") {
				msg.WriteRune(p.XChar())
			}
			p.XTake(")")
			clause["message"] = "(" + msg.String() + ")"
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
			clause[key] = val.String()
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
