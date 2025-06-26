// Package dkim (DomainKeys Identified Mail signatures, RFC 6376) signs and
// verifies DKIM signatures.
//
// Signatures are added to email messages in DKIM-Signature headers. By signing a
// message, a domain takes responsibility for the message. A message can have
// signatures for multiple domains, and the domain does not necessarily have to
// match a domain in a From header. Receiving mail servers can build a spaminess
// reputation based on domains that signed the message, along with other
// mechanisms.
package dkim

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/loredanacirstea/mailverif/dns"
	moxio "github.com/loredanacirstea/mailverif/utils"
	smtp "github.com/loredanacirstea/mailverif/utils"
	utils "github.com/loredanacirstea/mailverif/utils"
)

// If set, signatures for top-level domain "localhost" are accepted.
var Localserve bool

// Status is the result of verifying a DKIM-Signature as described by RFC 8601,
// "Message Header Field for Indicating Message Authentication Status".
type Status string

// ../rfc/8601:959 ../rfc/6376:1770 ../rfc/6376:2459

const (
	StatusNone      Status = "none"      // Message was not signed.
	StatusPass      Status = "pass"      // Message was signed and signature was verified.
	StatusFail      Status = "fail"      // Message was signed, but signature was invalid.
	StatusPolicy    Status = "policy"    // Message was signed, but signature is not accepted by policy.
	StatusNeutral   Status = "neutral"   // Message was signed, but the signature contains an error or could not be processed. This status is also used for errors not covered by other statuses.
	StatusTemperror Status = "temperror" // Message could not be verified. E.g. because of DNS resolve error. A later attempt may succeed. A missing DNS record is treated as temporary error, a new key may not have propagated through DNS shortly after it was taken into use.
	StatusPermerror Status = "permerror" // Message cannot be verified. E.g. when a required header field is absent or for invalid (combination of) parameters. Typically set if a DNS record does not allow the signature, e.g. due to algorithm mismatch or expiry.
)

// Lookup errors.
var (
	ErrNoRecord        = errors.New("dkim: no dkim dns record for selector and domain")
	ErrMultipleRecords = errors.New("dkim: multiple dkim dns record for selector and domain")
	ErrDNS             = errors.New("dkim: lookup of dkim dns record")
	ErrSyntax          = errors.New("dkim: syntax error in dkim dns record")
)

// Signature verification errors.
var (
	ErrSigAlgMismatch          = errors.New("dkim: signature algorithm mismatch with dns record")
	ErrHashAlgNotAllowed       = errors.New("dkim: hash algorithm not allowed by dns record")
	ErrKeyNotForEmail          = errors.New("dkim: dns record not allowed for use with email")
	ErrDomainIdentityMismatch  = errors.New("dkim: dns record disallows mismatch of domain (d=) and identity (i=)")
	ErrSigExpired              = errors.New("dkim: signature has expired")
	ErrHashAlgorithmUnknown    = errors.New("dkim: unknown hash algorithm")
	ErrBodyhashMismatch        = errors.New("dkim: body hash does not match")
	ErrSigVerify               = errors.New("dkim: signature verification failed")
	ErrSigAlgorithmUnknown     = errors.New("dkim: unknown signature algorithm")
	ErrCanonicalizationUnknown = errors.New("dkim: unknown canonicalization")
	ErrHeaderMalformed         = errors.New("dkim: mail message header is malformed")
	ErrFrom                    = errors.New("dkim: bad from headers")
	ErrQueryMethod             = errors.New("dkim: no recognized query method")
	ErrKeyRevoked              = errors.New("dkim: key has been revoked")
	ErrTLD                     = errors.New("dkim: signed domain is top-level domain, above organizational domain")
	ErrPolicy                  = errors.New("dkim: signature rejected by policy")
	ErrWeakKey                 = errors.New("dkim: key is too weak, need at least 1024 bits for rsa")
)

const DKIM_SIGNATURE_HEADER = "DKIM-Signature"
const DKIM_SIGNATURE_HEADER_LOW = "dkim-signature"

// Pre‑declared DKIM spec (public so callers may copy & tweak for ARC).
var DKIMSpec = Spec{
	HeaderName: "DKIM-Signature",
	// ../rfc/6376:2532
	RequiredTags:         []string{"v", "a", "b", "bh", "d", "h", "s"},
	CanonicalizationDef:  "simple/simple",
	PolicySig:            DefaultPolicy,
	PolicyHeader:         DefaultHeadersPolicy,
	PolicyParsing:        DefaultParsingPolicy,
	CheckSignatureParams: CheckSignatureParamsDKIM,
	NewSigWithDefaults:   NewDKIMSigWithDefaults,
}

// Result is the conclusion of verifying one DKIM-Signature header. An email can
// have multiple signatures, each with different parameters.
//
// To decide what to do with a message, both the signature parameters and the DNS
// TXT record have to be consulted.
type Result struct {
	Status          Status
	Sig             *Sig    // Parsed form of DKIM-Signature header. Can be nil for invalid DKIM-Signature header.
	Record          *Record // Parsed form of DKIM DNS record for selector and domain in Sig. Optional.
	RecordAuthentic bool    // Whether DKIM DNS record was DNSSEC-protected. Only valid if Sig is non-nil.
	Expired         bool
	Err             error // If Status is not StatusPass, this error holds the details and can be checked using errors.Is.
}

// todo: use some io.Writer to hash the body and the header.

// Selector holds selectors and key material to generate DKIM signatures.
type Selector struct {
	Hash          string   // "sha256" or the older "sha1".
	HeaderRelaxed bool     // If the header is canonicalized in relaxed instead of simple mode.
	BodyRelaxed   bool     // If the body is canonicalized in relaxed instead of simple mode.
	Headers       []string // Headers to include in signature.

	// Whether to "oversign" headers, ensuring additional/new values of existing
	// headers cannot be added.
	SealHeaders bool

	// If > 0, period a signature is valid after signing, as duration, e.g. 72h. The
	// period should be enough for delivery at the final destination, potentially with
	// several hops/relays. In the order of days at least.
	Expiration time.Duration

	PrivateKey crypto.Signer // Either an *rsa.PrivateKey or ed25519.PrivateKey.
	Domain     dns.Domain    // Of selector only, not FQDN.
}

func NewDKIMSigWithDefaults() *Sig {
	return &Sig{
		HeaderName:       DKIM_SIGNATURE_HEADER,
		Canonicalization: "simple/simple",
		Length:           -1,
		SignTime:         -1,
		ExpireTime:       -1,
		Version:          1,
	}
}

// Sign returns line(s) with DKIM-Signature headers, generated according to the configuration.
func Sign(elog *slog.Logger, local smtp.Localpart, domain dns.Domain, selectors []Selector, smtputf8 bool, msg io.ReaderAt, now func() time.Time) ([]string, error) {

	hdrs, bodyOffset, err := utils.ParseHeaders(bufio.NewReader(&moxio.AtReader{R: msg}))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrHeaderMalformed, err)
	}

	sigs, err := BuildSignatureGeneric(elog, DKIMSpec, hdrs, bodyOffset, domain, selectors, smtputf8, msg, now)
	if err != nil {
		return nil, err
	}
	for _, sig := range sigs {
		sig.Identity = &Identity{&local, domain}
	}
	return SignGeneric(sigs, hdrs)
}

// Verify parses the DKIM-Signature headers in a message and verifies each of them.
//
// If the headers of the message cannot be found, an error is returned.
// Otherwise, each DKIM-Signature header is reflected in the returned results.
//
// NOTE: Verify does not check if the domain (d=) that signed the message is
// the domain of the sender. The caller, e.g. through DMARC, should do this.
//
// If ignoreTestMode is true and the DKIM record is in test mode (t=y), a
// verification failure is treated as actual failure. With ignoreTestMode
// false, such verification failures are treated as if there is no signature by
// returning StatusNone.
func Verify(elog *slog.Logger, resolver dns.Resolver, smtputf8 bool, policy func(*Sig) error, r io.ReaderAt, ignoreTest, strictExpiration bool, now func() time.Time, rec *Record) ([]Result, error) {
	// allow custom policy override while still using DKIMSpec.
	spec := DKIMSpec
	if policy != nil {
		spec.PolicySig = policy
	}
	return VerifyGeneric(elog, spec, resolver, smtputf8, r, ignoreTest, strictExpiration, now, rec)
}

// check if signature is acceptable.
// Only looks at the signature parameters, not at the DNS record.
func CheckSignatureParamsDKIM(sig *Sig) error {
	// "From" header is required, ../rfc/6376:2122 ../rfc/6376:2546
	var from bool
	for _, h := range sig.SignedHeaders {
		if strings.EqualFold(h, "from") {
			from = true
			break
		}
	}
	if !from {
		return fmt.Errorf(`%w: required "from" header not signed`, ErrFrom)
	}
	return nil
}

// Lookup looks up the DKIM TXT record and parses it.
//
// A requested record is <selector>._domainkey.<domain>. Exactly one valid DKIM
// record should be present.
//
// authentic indicates if DNS results were DNSSEC-verified.
func Lookup(elog *slog.Logger, resolver dns.Resolver, selector, domain dns.Domain) (rstatus Status, rrecord *Record, rtxt string, authentic bool, rerr error) {
	defer func() {
		errstr := ""
		if rerr != nil {
			errstr = rerr.Error()
		}
		elog.Debug("dkim lookup result", errstr,
			slog.Any("selector", selector),
			slog.Any("domain", domain),
			slog.Any("status", rstatus),
			slog.Any("record", rrecord))
	}()

	name := selector.ASCII + "._domainkey." + domain.ASCII + "."
	records, lookupResult, err := resolver.LookupTXT(name)
	if dns.IsNotFound(err) {
		// ../rfc/6376:2608
		// We must return StatusPermerror. We may want to return StatusTemperror because in
		// practice someone will start using a new key before DNS changes have propagated.
		return StatusPermerror, nil, "", lookupResult.Authentic, fmt.Errorf("%w: dns name %q", ErrNoRecord, name)
	} else if err != nil {
		return StatusTemperror, nil, "", lookupResult.Authentic, fmt.Errorf("%w: dns name %q: %s", ErrDNS, name, err)
	}

	// ../rfc/6376:2612
	var status = StatusTemperror
	var record *Record
	var txt string
	err = nil
	for _, s := range records {
		// We interpret ../rfc/6376:2621 to mean that a record that claims to be v=DKIM1,
		// but isn't actually valid, results in a StatusPermFail. But a record that isn't
		// claiming to be DKIM1 is ignored.
		var r *Record
		var isdkim bool
		r, isdkim, err = ParseRecord(s)
		if err != nil && isdkim {
			return StatusPermerror, nil, txt, lookupResult.Authentic, fmt.Errorf("%w: %s", ErrSyntax, err)
		} else if err != nil {
			// Hopefully the remote MTA admin discovers the configuration error and fix it for
			// an upcoming delivery attempt, in case we rejected with temporary status.
			status = StatusTemperror
			err = fmt.Errorf("%w: not a dkim record: %s", ErrSyntax, err)
			continue
		}
		// If there are multiple valid records, return a temporary error. Perhaps the error is fixed soon.
		// ../rfc/6376:1609
		// ../rfc/6376:2584
		if record != nil {
			return StatusTemperror, nil, "", lookupResult.Authentic, fmt.Errorf("%w: dns name %q", ErrMultipleRecords, name)
		}
		record = r
		txt = s
		err = nil
	}

	if record == nil {
		return status, nil, "", lookupResult.Authentic, err
	}
	return StatusNeutral, record, txt, lookupResult.Authentic, nil
}

// lookup the public key in the DNS and verify the signature.
func VerifySignature(elog *slog.Logger, resolver dns.Resolver, sig *Sig, hash crypto.Hash, canonHeaderSimple, canonDataSimple bool, hdrs []utils.Header, verifySig []byte, body *bufio.Reader, ignoreTestMode bool, record *Record) (Status, *Record, bool, error) {
	var status Status
	var err error
	var authentic bool = false
	if record == nil {
		// ../rfc/6376:2604
		status, record, _, authentic, err = Lookup(elog, resolver, sig.Selector, sig.Domain)
		if err != nil {
			// todo: for temporary errors, we could pass on information so caller returns a 4.7.5 ecode, ../rfc/6376:2777
			return status, nil, authentic, err
		}
	}
	status, err = VerifySignatureRecord(record, sig, hash, canonHeaderSimple, canonDataSimple, hdrs, verifySig, body, ignoreTestMode)
	return status, record, authentic, err
}

// verify a DKIM signature given the record from dns and signature from the email message.
func VerifySignatureRecord(r *Record, sig *Sig, hash crypto.Hash, canonHeaderSimple, canonDataSimple bool, hdrs []utils.Header, verifySig []byte, body *bufio.Reader, ignoreTestMode bool) (rstatus Status, rerr error) {
	if !ignoreTestMode {
		// ../rfc/6376:1558
		y := false
		for _, f := range r.Flags {
			if strings.EqualFold(f, "y") {
				y = true
				break
			}
		}
		if y {
			defer func() {
				if rstatus != StatusPass {
					rstatus = StatusNone
				}
			}()
		}
	}

	// ../rfc/6376:2639
	if len(r.Hashes) > 0 {
		ok := false
		for _, h := range r.Hashes {
			if strings.EqualFold(h, sig.AlgorithmHash) {
				ok = true
				break
			}
		}
		if !ok {
			return StatusPermerror, fmt.Errorf("%w: dkim dns record expects one of %q, message uses %q", ErrHashAlgNotAllowed, strings.Join(r.Hashes, ","), sig.AlgorithmHash)
		}
	}

	// ../rfc/6376:2651
	if !strings.EqualFold(r.Key, sig.AlgorithmSign) {
		return StatusPermerror, fmt.Errorf("%w: dkim dns record requires algorithm %q, message has %q", ErrSigAlgMismatch, r.Key, sig.AlgorithmSign)
	}

	// ../rfc/6376:2645
	if r.PublicKey == nil {
		return StatusPermerror, ErrKeyRevoked
	} else if rsaKey, ok := r.PublicKey.(*rsa.PublicKey); ok && rsaKey.N.BitLen() < 1024 {
		// ../rfc/8301:157
		return StatusPermerror, ErrWeakKey
	}

	// ../rfc/6376:1541
	if !r.ServiceAllowed("email") {
		return StatusPermerror, ErrKeyNotForEmail
	}
	for _, t := range r.Flags {
		// ../rfc/6376:1575
		// ../rfc/6376:1805
		if strings.EqualFold(t, "s") && sig.Identity != nil {
			if sig.Identity.Domain.ASCII != sig.Domain.ASCII {
				return StatusPermerror, fmt.Errorf("%w: i= identity domain %q must match d= domain %q", ErrDomainIdentityMismatch, sig.Domain.ASCII, sig.Identity.Domain.ASCII)
			}
		}
	}

	if sig.Length >= 0 {
		// todo future: implement l= parameter in signatures. we don't currently allow this through policy check.
		return StatusPermerror, fmt.Errorf("l= (length) parameter in signature not yet implemented")
	}

	// We first check the signature is with the claimed body hash is valid. Then we
	// verify the body hash. In case of invalid signatures, we won't read the entire
	// body.
	// ../rfc/6376:1700
	// ../rfc/6376:2656

	dh, err := DataHash(hash.New(), canonHeaderSimple, sig, hdrs, verifySig)
	if err != nil {
		// Any error is likely an invalid header field in the message, hence permanent error.
		return StatusPermerror, fmt.Errorf("calculating data hash: %w", err)
	}

	switch k := r.PublicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(k, hash, dh, sig.Signature); err != nil {
			return StatusFail, fmt.Errorf("%w: rsa verification: %s", ErrSigVerify, err)
		}
	case ed25519.PublicKey:
		if ok := ed25519.Verify(k, dh, sig.Signature); !ok {
			return StatusFail, fmt.Errorf("%w: ed25519 verification", ErrSigVerify)
		}
	default:
		return StatusPermerror, fmt.Errorf("%w: unrecognized signature algorithm %q", ErrSigAlgorithmUnknown, r.Key)
	}

	bh, err := BodyHash(hash.New(), canonDataSimple, body)
	if err != nil {
		// Any error is likely some internal error, hence temporary error.
		return StatusTemperror, fmt.Errorf("calculating body hash: %w", err)
	}
	if !bytes.Equal(sig.BodyHash, bh) {
		return StatusFail, fmt.Errorf("%w: signature bodyhash %x != calculated bodyhash %x", ErrBodyhashMismatch, sig.BodyHash, bh)
	}

	return StatusPass, nil
}

func algHash(s string) (crypto.Hash, bool) {
	if strings.EqualFold(s, "sha1") {
		return crypto.SHA1, true
	} else if strings.EqualFold(s, "sha256") {
		return crypto.SHA256, true
	}
	return 0, false
}

// bodyHash calculates the hash over the body.
func BodyHash(h hash.Hash, canonSimple bool, body *bufio.Reader) ([]byte, error) {
	// todo: take l= into account. we don't currently allow it for policy reasons.

	var crlf = []byte("\r\n")

	if canonSimple {
		// ../rfc/6376:864, ensure body ends with exactly one trailing crlf.
		ncrlf := 0
		for {
			buf, err := body.ReadBytes('\n')
			if len(buf) == 0 && err == io.EOF {
				break
			}
			if err != nil && err != io.EOF {
				return nil, err
			}
			hascrlf := bytes.HasSuffix(buf, crlf)
			if hascrlf {
				buf = buf[:len(buf)-2]
			}
			if len(buf) > 0 {
				for ; ncrlf > 0; ncrlf-- {
					h.Write(crlf)
				}
				h.Write(buf)
			}
			if hascrlf {
				ncrlf++
			}
		}
		h.Write(crlf)
	} else {
		hb := bufio.NewWriter(h)

		// We go through the body line by line, replacing WSP with a single space and removing whitespace at the end of lines.
		// We stash "empty" lines. If they turn out to be at the end of the file, we must drop them.
		stash := &bytes.Buffer{}
		var line bool         // Whether buffer read is for continuation of line.
		var prev byte         // Previous byte read for line.
		linesEmpty := true    // Whether stash contains only empty lines and may need to be dropped.
		var bodynonempty bool // Whether body is non-empty, for adding missing crlf.
		var hascrlf bool      // Whether current/last line ends with crlf, for adding missing crlf.
		for {
			// todo: should not read line at a time, count empty lines. reduces max memory usage. a message with lots of empty lines can cause high memory use.
			buf, err := body.ReadBytes('\n')
			if len(buf) == 0 && err == io.EOF {
				break
			}
			if err != nil && err != io.EOF {
				return nil, err
			}
			bodynonempty = true

			hascrlf = bytes.HasSuffix(buf, crlf)
			if hascrlf {
				buf = buf[:len(buf)-2]

				// ../rfc/6376:893, "ignore all whitespace at the end of lines".
				// todo: what is "whitespace"? it isn't WSP (space and tab), the next line mentions WSP explicitly for another rule. should we drop trailing \r, \n, \v, more?
				buf = bytes.TrimRight(buf, " \t")
			}

			// Replace one or more WSP to a single SP.
			for i, c := range buf {
				wsp := c == ' ' || c == '\t'
				if (i >= 0 || line) && wsp {
					if prev == ' ' {
						continue
					}
					prev = ' '
					c = ' '
				} else {
					prev = c
				}
				if !wsp {
					linesEmpty = false
				}
				stash.WriteByte(c)
			}
			if hascrlf {
				stash.Write(crlf)
			}
			line = !hascrlf
			if !linesEmpty {
				hb.Write(stash.Bytes())
				stash.Reset()
				linesEmpty = true
			}
		}
		// ../rfc/6376:886
		// Only for non-empty bodies without trailing crlf do we add the missing crlf.
		if bodynonempty && !hascrlf {
			hb.Write(crlf)
		}

		hb.Flush()
	}
	return h.Sum(nil), nil
}

func DataHash(h hash.Hash, canonSimple bool, sig *Sig, hdrs []utils.Header, verifySig []byte) ([]byte, error) {
	headers := ""
	revHdrs := map[string][]utils.Header{}
	for _, h := range hdrs {
		revHdrs[h.LKey] = append([]utils.Header{h}, revHdrs[h.LKey]...)
	}

	for _, key := range sig.SignedHeaders {
		lkey := strings.ToLower(key)
		h := revHdrs[lkey]
		if len(h) == 0 {
			continue
		}
		revHdrs[lkey] = h[1:]
		s := string(h[0].Raw)
		if canonSimple {
			// ../rfc/6376:823
			// Add unmodified.
			headers += s
		} else {
			ch, err := relaxedCanonicalHeaderWithoutCRLF(s)
			if err != nil {
				return nil, fmt.Errorf("canonicalizing header: %w", err)
			}
			headers += ch + "\r\n"
		}
	}
	// ../rfc/6376:2377, canonicalization does not apply to the dkim-signature header.
	h.Write([]byte(headers))
	dkimSig := verifySig
	if !canonSimple {
		ch, err := relaxedCanonicalHeaderWithoutCRLF(string(verifySig))
		if err != nil {
			return nil, fmt.Errorf("canonicalizing DKIM-Signature header: %w", err)
		}
		dkimSig = []byte(ch)
	}
	h.Write(dkimSig)
	return h.Sum(nil), nil
}

// a single header, can be multiline.
func relaxedCanonicalHeaderWithoutCRLF(s string) (string, error) {
	// ../rfc/6376:831
	t := strings.SplitN(s, ":", 2)
	if len(t) != 2 {
		return "", fmt.Errorf("%w: invalid header %q", ErrHeaderMalformed, s)
	}

	// Unfold, we keep the leading WSP on continuation lines and fix it up below.
	v := strings.ReplaceAll(t[1], "\r\n", "")

	// Replace one or more WSP to a single SP.
	var nv []byte
	var prev byte
	for i, c := range []byte(v) {
		if i >= 0 && c == ' ' || c == '\t' {
			if prev == ' ' {
				continue
			}
			prev = ' '
			c = ' '
		} else {
			prev = c
		}
		nv = append(nv, c)
	}

	ch := strings.ToLower(strings.TrimRight(t[0], " \t")) + ":" + strings.Trim(string(nv), " \t")
	return ch, nil
}
