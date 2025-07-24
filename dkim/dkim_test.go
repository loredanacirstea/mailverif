package dkim

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	testutils "github.com/loredanacirstea/mailverif/_testutils"
	"github.com/loredanacirstea/mailverif/dns"
	utils "github.com/loredanacirstea/mailverif/utils"
)

var pkglog = slog.New(slog.NewTextHandler(os.Stdout, nil))

var timeNow = func() time.Time {
	return time.Now()
}

func policyOK(sig *Sig) error {
	return nil
}

func TestParseSignature(t *testing.T) {
	// Domain name must always be A-labels, not U-labels. We do allow localpart with non-ascii.
	hdr := `DKIM-Signature: v=1; a=rsa-sha256; d=xn--h-bga.mox.example; s=xn--yr2021-pua;
        i=møx@xn--h-bga.mox.example; t=1643719203; h=From:To:Cc:Bcc:Reply-To:
        References:In-Reply-To:Subject:Date:Message-ID:Content-Type:From:To:Subject:
        Date:Message-ID:Content-Type;
        bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=; b=dtgAOl71h/dNPQrmZTi3SBVkm+
        EjMnF7sWGT123fa5g+m6nGpPue+I+067wwtkWQhsedbDkqT7gZb5WaG5baZsr9e/XpJ/iX4g6YXpr
        07aLY8eF9jazcGcRCVCqLtyq0UJQ2Oz/ML74aYu1beh3jXsoI+k3fJ+0/gKSVC7enCFpNe1HhbXVS
        4HRy/Rw261OEIy2e20lyPT4iDk2oODabzYa28HnXIciIMELjbc/sSawG68SAnhwdkWBrRzBDMCCHm
        wvkmgDsVJWtdzjJqjxK2mYVxBMJT0lvsutXgYQ+rr6BLtjHsOb8GMSbQGzY5SJ3N8TP02pw5OykBu
        B/aHff1A==
`
	smtputf8 := true
	_, err := ParseSignature(&utils.Header{Key: DKIM_SIGNATURE_HEADER, Raw: []byte(strings.ReplaceAll(hdr, "\n", "\r\n"))}, smtputf8, DKIMSpec.RequiredTags, DKIMSpec.PolicyParsing, DKIMSpec.NewSigWithDefaults)
	if err != nil {
		t.Fatalf("parsing signature: %s", err)
	}
}

func TestVerifyRSA(t *testing.T) {
	message := strings.ReplaceAll(`Return-Path: <mechiel@ueber.net>
X-Original-To: mechiel@ueber.net
Delivered-To: mechiel@ueber.net
Received: from [IPV6:2a02:a210:4a3:b80:ca31:30ee:74a7:56e0] (unknown [IPv6:2a02:a210:4a3:b80:ca31:30ee:74a7:56e0])
	by koriander.ueber.net (Postfix) with ESMTPSA id E119EDEB0B
	for <mechiel@ueber.net>; Fri, 10 Dec 2021 20:09:08 +0100 (CET)
DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=ueber.net;
	s=koriander; t=1639163348;
	bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;
	h=Date:To:From:Subject:From;
	b=rpWruWprs2TB7/MnulA2n2WtfUIfrrnAvRoSrip1ruX5ORN4AOYPPMmk/gGBDdc6O
	 grRpSsNzR9BrWcooYfbNfSbl04nPKMp0acsZGfpvkj0+mqk5b8lqZs3vncG1fHlQc7
	 0KXfnAHyEs7bjyKGbrw2XG1p/EDoBjIjUsdpdCAtamMGv3A3irof81oSqvwvi2KQks
	 17aB1YAL9Xzkq9ipo1aWvDf2W6h6qH94YyNocyZSVJ+SlVm3InNaF8APkV85wOm19U
	 9OW81eeuQbvSPcQZJVOmrWzp7XKHaXH0MYE3+hdH/2VtpCnPbh5Zj9SaIgVbaN6NPG
	 Ua0E07rwC86sg==
Message-ID: <427999f6-114f-e59c-631e-ab2a5f6bfe4c@ueber.net>
Date: Fri, 10 Dec 2021 20:09:08 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.4.0
Content-Language: nl
To: mechiel@ueber.net
From: Mechiel Lukkien <mechiel@ueber.net>
Subject: test
Content-Type: text/plain; charset=UTF-8; format=flowed
Content-Transfer-Encoding: 7bit

test
`, "\n", "\r\n")

	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"koriander._domainkey.ueber.net.": {"v=DKIM1; k=rsa; s=email; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy3Z9ffZe8gUTJrdGuKj6IwEembmKYpp0jMa8uhudErcI4gFVUaFiiRWxc4jP/XR9NAEv3XwHm+CVcHu+L/n6VWt6g59U7vHXQicMfKGmEp2VplsgojNy/Y5X9HdVYM0azsI47NcJCDW9UVfeOHdOSgFME4F8dNtUKC4KTB2d1pqj/yixz+V8Sv8xkEyPfSRHcNXIw0LvelqJ1MRfN3hO/3uQSVrPYYk4SyV0b6wfnkQs28fpiIpGQvzlGI5WkrdOQT5k4YHaEvZDLNdwiMeVZOEL7dDoFs2mQsovm+tH0StUAZTnr61NLVFfD5V6Ip1V9zVtspPHvYSuOWwyArFZ9QIDAQAB"},
		},
	}

	results, err := Verify2(pkglog, resolver, false, policyOK, []byte(message), false, false, true, timeNow, nil)
	if err != nil {
		t.Fatalf("dkim verify: %v", err)
	}
	if len(results) != 1 || results[0].Status != StatusPass {
		t.Fatalf("verify: unexpected results %v", results)
	}
}

func TestVerifyEd25519(t *testing.T) {
	// ../rfc/8463:287
	message := strings.ReplaceAll(`DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;
 d=football.example.com; i=@football.example.com;
 q=dns/txt; s=brisbane; t=1528637909; h=from : to :
 subject : date : message-id : from : subject : date;
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus
 Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
 d=football.example.com; i=@football.example.com;
 q=dns/txt; s=test; t=1528637909; h=from : to : subject :
 date : message-id : from : subject : date;
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3
 DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz
 dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=
From: Joe SixPack <joe@football.example.com>
To: Suzie Q <suzie@shopping.example.net>
Subject: Is dinner ready?
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
Message-ID: <20030712040037.46341.5F8J@football.example.com>

Hi.

We lost the game.  Are you hungry yet?

Joe.

`, "\n", "\r\n")

	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"brisbane._domainkey.football.example.com.": {"v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="},
			"test._domainkey.football.example.com.":     {"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB"},
		},
	}

	results, err := Verify2(pkglog, resolver, false, policyOK, []byte(message), false, false, true, timeNow, nil)
	if err != nil {
		t.Fatalf("dkim verify: %v", err)
	}
	if len(results) != 2 || results[0].Status != StatusPass || results[1].Status != StatusPass {
		t.Fatalf("verify: unexpected results %#v", results)
	}
}

func TestSign(t *testing.T) {
	message := strings.ReplaceAll(`Message-ID: <427999f6-114f-e59c-631e-ab2a5f6bfe4c@ueber.net>
Date: Fri, 10 Dec 2021 20:09:08 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.4.0
Content-Language: nl
To: mechiel@ueber.net
From: Mechiel Lukkien <mechiel@ueber.net>
Subject: test
 test
Content-Type: text/plain; charset=UTF-8; format=flowed
Content-Transfer-Encoding: 7bit

test
`, "\n", "\r\n")

	rsaKey := testutils.GetRSAKey(t)
	ed25519Key := ed25519.NewKeyFromSeed(make([]byte, 32))

	selrsa := Selector{
		Hash:       "sha256",
		PrivateKey: rsaKey,
		Headers:    strings.Split("From,To,Cc,Bcc,Reply-To,References,In-Reply-To,Subject,Date,Message-ID,Content-Type", ","),
		Domain:     dns.Domain{ASCII: "testrsa"},
	}

	// Now with sha1 and relaxed canonicalization.
	selrsa2 := Selector{
		Hash:       "sha1",
		PrivateKey: rsaKey,
		Headers:    strings.Split("From,To,Cc,Bcc,Reply-To,References,In-Reply-To,Subject,Date,Message-ID,Content-Type", ","),
		Domain:     dns.Domain{ASCII: "testrsa2"},
	}
	selrsa2.HeaderRelaxed = true
	selrsa2.BodyRelaxed = true

	// Ed25519 key.
	seled25519 := Selector{
		Hash:       "sha256",
		PrivateKey: ed25519Key,
		Headers:    strings.Split("From,To,Cc,Bcc,Reply-To,References,In-Reply-To,Subject,Date,Message-ID,Content-Type", ","),
		Domain:     dns.Domain{ASCII: "tested25519"},
	}
	// Again ed25519, but without sealing headers. Use sha256 again, for reusing the body hash from the previous dkim-signature.
	seled25519b := Selector{
		Hash:        "sha256",
		PrivateKey:  ed25519Key,
		Headers:     strings.Split("From,To,Cc,Bcc,Reply-To,Subject,Date", ","),
		SealHeaders: true,
		Domain:      dns.Domain{ASCII: "tested25519b"},
	}
	selectors := []Selector{selrsa, selrsa2, seled25519, seled25519b}

	r := []byte(message)
	newhdrs, err := Sign2(pkglog, "mjl", dns.Domain{ASCII: "mox.example"}, selectors, false, r, timeNow)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	headers := utils.SerializeHeaders(newhdrs)

	makeRecord := func(k string, publicKey any) string {
		tr := &Record{
			Version:   "DKIM1",
			Key:       k,
			PublicKey: publicKey,
			Flags:     []string{"s"},
		}
		txt, err := tr.Record()
		if err != nil {
			t.Fatalf("making dns txt record: %s", err)
		}
		//log.Infof("txt record: %s", txt)
		return txt
	}

	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"testrsa._domainkey.mox.example.":      {makeRecord("rsa", rsaKey.Public())},
			"testrsa2._domainkey.mox.example.":     {makeRecord("rsa", rsaKey.Public())},
			"tested25519._domainkey.mox.example.":  {makeRecord("ed25519", ed25519Key.Public())},
			"tested25519b._domainkey.mox.example.": {makeRecord("ed25519", ed25519Key.Public())},
		},
	}

	nmsg := headers + message
	results, err := Verify2(pkglog, resolver, false, policyOK, []byte(nmsg), false, false, true, timeNow, nil)
	if err != nil {
		t.Fatalf("verify: %s", err)
	}
	if len(results) != 4 || results[0].Status != StatusPass || results[1].Status != StatusPass || results[2].Status != StatusPass || results[3].Status != StatusPass {
		t.Fatalf("verify: unexpected results %v\nheaders:\n%s", results, headers)
	}
	// log.Infof("headers:%s", headers)
	// log.Infof("nmsg\n%s", nmsg)

	// Multiple From headers.
	r = []byte("From: <mjl@mox.example>\r\nFrom: <mjl@mox.example>\r\n\r\ntest")
	_, err = Sign2(pkglog, "mjl", dns.Domain{ASCII: "mox.example"}, selectors, false, r, timeNow)
	if !errors.Is(err, ErrFrom) {
		t.Fatalf("sign, got err %v, expected ErrFrom", err)
	}

	// No From header.
	r = []byte("Brom: <mjl@mox.example>\r\n\r\ntest")
	_, err = Sign2(pkglog, "mjl", dns.Domain{ASCII: "mox.example"}, selectors, false, r, timeNow)
	if !errors.Is(err, ErrFrom) {
		t.Fatalf("sign, got err %v, expected ErrFrom", err)
	}

	// Malformed headers.
	r = []byte(":\r\n\r\ntest")
	_, err = Sign2(pkglog, "mjl", dns.Domain{ASCII: "mox.example"}, selectors, false, r, timeNow)
	if !errors.Is(err, ErrHeaderMalformed) {
		t.Fatalf("sign, got err %v, expected ErrHeaderMalformed", err)
	}

	r = []byte(" From:<mjl@mox.example>\r\n\r\ntest")
	_, err = Sign2(pkglog, "mjl", dns.Domain{ASCII: "mox.example"}, selectors, false, r, timeNow)
	if !errors.Is(err, ErrHeaderMalformed) {
		t.Fatalf("sign, got err %v, expected ErrHeaderMalformed", err)
	}

	r = []byte("Frøm:<mjl@mox.example>\r\n\r\ntest")
	_, err = Sign2(pkglog, "mjl", dns.Domain{ASCII: "mox.example"}, selectors, false, r, timeNow)
	if !errors.Is(err, ErrHeaderMalformed) {
		t.Fatalf("sign, got err %v, expected ErrHeaderMalformed", err)
	}

	r = []byte("From:<mjl@mox.example>")
	_, err = Sign2(pkglog, "mjl", dns.Domain{ASCII: "mox.example"}, selectors, false, r, timeNow)
	if !errors.Is(err, ErrHeaderMalformed) {
		t.Fatalf("sign, got err %v, expected ErrHeaderMalformed", err)
	}
}

func TestVerify(t *testing.T) {
	// We do many Verify calls, each time starting out with a valid configuration, then
	// we modify one thing to trigger an error, which we check for.

	const message = `From: <mjl@mox.example>
To: <other@mox.example>
Subject: test
Date: Fri, 10 Dec 2021 20:09:08 +0100
Message-ID: <test@mox.example>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8; format=flowed
Content-Transfer-Encoding: 7bit

test
`

	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	var resolver dns.MockResolver
	var record *Record
	var recordTxt string
	var msg string
	var policy func(*Sig) error
	var sel Selector
	var selectors []Selector
	var signed bool
	var signDomain dns.Domain

	prepare := func() {
		t.Helper()

		policy = DefaultPolicy
		signDomain = dns.Domain{ASCII: "mox.example"}

		record = &Record{
			Version:   "DKIM1",
			Key:       "ed25519",
			PublicKey: key.Public(),
			Flags:     []string{"s"},
		}

		txt, err := record.Record()
		if err != nil {
			t.Fatalf("making dns txt record: %s", err)
		}
		recordTxt = txt

		resolver = dns.MockResolver{
			TXT: map[string][]string{
				"test._domainkey.mox.example.": {txt},
			},
		}

		sel = Selector{
			Hash:       "sha256",
			PrivateKey: key,
			Headers:    strings.Split("From,To,Cc,Bcc,Reply-To,References,In-Reply-To,Subject,Date,Message-ID,Content-Type", ","),
			Domain:     dns.Domain{ASCII: "test"},
		}
		selectors = []Selector{sel}

		msg = message
		signed = false
	}

	sign := func() {
		t.Helper()

		msg = strings.ReplaceAll(msg, "\n", "\r\n")
		r := []byte(msg)
		newhdrs, err := Sign2(pkglog, "mjl", signDomain, selectors, false, r, timeNow)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		headers := utils.SerializeHeaders(newhdrs)
		msg = headers + msg
		signed = true
	}

	test := func(expErr error, expStatus Status, expResultErr error, mod func()) {
		t.Helper()

		prepare()
		mod()
		if !signed {
			sign()
		}

		results, err := Verify2(pkglog, resolver, true, policy, []byte(msg), false, false, true, timeNow, nil)
		if (err == nil) != (expErr == nil) || err != nil && !errors.Is(err, expErr) {
			t.Fatalf("got verify error %v, expected %v", err, expErr)
		}
		if expStatus != "" && (len(results) == 0 || results[0].Status != expStatus) {
			var status Status
			if len(results) > 0 {
				status = results[0].Status
			}
			t.Fatalf("got status %q, expected %q", status, expStatus)
		}
		var resultErr error
		if len(results) > 0 {
			resultErr = results[0].Err
		}
		if (resultErr == nil) != (expResultErr == nil) || resultErr != nil && !errors.Is(resultErr, expResultErr) {
			t.Fatalf("got result error %v, expected %v", resultErr, expResultErr)
		}
	}

	test(nil, StatusPass, nil, func() {})

	// Cannot parse message, so not much more to do.
	test(ErrHeaderMalformed, "", nil, func() {
		sign()
		msg = ":\r\n\r\n" // Empty header key.
	})

	// From Lookup.
	// No DKIM record. ../rfc/6376:2608
	test(nil, StatusPermerror, ErrNoRecord, func() {
		resolver.TXT = nil
	})
	// DNS request is failing temporarily.
	test(nil, StatusTemperror, ErrDNS, func() {
		resolver.Fail = []string{
			"txt test._domainkey.mox.example.",
		}
	})
	// Claims to be DKIM through v=, but cannot be parsed. ../rfc/6376:2621
	test(nil, StatusPermerror, ErrSyntax, func() {
		resolver.TXT = map[string][]string{
			"test._domainkey.mox.example.": {"v=DKIM1; bogus"},
		}
	})
	// Not a DKIM record. ../rfc/6376:2621
	test(nil, StatusTemperror, ErrSyntax, func() {
		resolver.TXT = map[string][]string{
			"test._domainkey.mox.example.": {"bogus"},
		}
	})
	// Multiple dkim records. ../rfc/6376:1609
	test(nil, StatusTemperror, ErrMultipleRecords, func() {
		resolver.TXT["test._domainkey.mox.example."] = []string{recordTxt, recordTxt}
	})

	// Invalid DKIM-Signature header. ../rfc/6376:2503
	test(nil, StatusPermerror, ErrSigMissingTag, func() {
		msg = strings.ReplaceAll("DKIM-Signature: v=1\n"+msg, "\n", "\r\n")
		signed = true
	})

	// Signature has valid syntax, but parameters aren't acceptable.
	// "From" not signed.  ../rfc/6376:2546
	test(nil, StatusPermerror, ErrFrom, func() {
		sign()
		// Remove "from" from signed headers (h=).
		msg = strings.ReplaceAll(msg, ":From:", ":")
		msg = strings.ReplaceAll(msg, "=From:", "=")
	})
	// todo: check expired signatures with StatusPermerror and ErrSigExpired. ../rfc/6376:2550
	// Domain in signature is higher-level than organizational domain. ../rfc/6376:2554
	test(nil, StatusPermerror, ErrTLD, func() {
		// Pretend to sign as .com
		msg = strings.ReplaceAll(msg, "From: <mjl@mox.example>\n", "From: <mjl@com>\n")
		signDomain = dns.Domain{ASCII: "com"}
		resolver.TXT = map[string][]string{
			"test._domainkey.com.": {recordTxt},
		}
	})
	// Unknown hash algorithm.
	test(nil, StatusPermerror, ErrHashAlgorithmUnknown, func() {
		sign()
		msg = strings.ReplaceAll(msg, "sha256", "sha257")
	})
	// Unknown canonicalization.
	test(nil, StatusPermerror, ErrCanonicalizationUnknown, func() {
		sel.HeaderRelaxed = true
		sel.BodyRelaxed = true
		selectors = []Selector{sel}

		sign()
		msg = strings.ReplaceAll(msg, "relaxed/relaxed", "bogus/bogus")
	})
	// Query methods without dns/txt. ../rfc/6376:1268
	test(nil, StatusPermerror, ErrQueryMethod, func() {
		sign()
		msg = strings.ReplaceAll(msg, "DKIM-Signature: ", "DKIM-Signature: q=other;")
	})

	// Unacceptable through policy. ../rfc/6376:2560
	test(nil, StatusPolicy, ErrPolicy, func() {
		sign()
		msg = strings.ReplaceAll(msg, "DKIM-Signature: ", "DKIM-Signature: l=1;")
	})
	// Hash algorithm not allowed by DNS record. ../rfc/6376:2639
	test(nil, StatusPermerror, ErrHashAlgNotAllowed, func() {
		recordTxt += ";h=sha1"
		resolver.TXT = map[string][]string{
			"test._domainkey.mox.example.": {recordTxt},
		}
	})
	// Signature algorithm mismatch. ../rfc/6376:2651
	test(nil, StatusPermerror, ErrSigAlgMismatch, func() {
		record.PublicKey = testutils.GetRSAKey(t).Public()
		record.Key = "rsa"
		txt, err := record.Record()
		if err != nil {
			t.Fatalf("making dns txt record: %s", err)
		}
		resolver.TXT = map[string][]string{
			"test._domainkey.mox.example.": {txt},
		}
	})
	// Empty public key means revoked key. ../rfc/6376:2645
	test(nil, StatusPermerror, ErrKeyRevoked, func() {
		record.PublicKey = nil
		txt, err := record.Record()
		if err != nil {
			t.Fatalf("making dns txt record: %s", err)
		}
		resolver.TXT = map[string][]string{
			"test._domainkey.mox.example.": {txt},
		}
	})
	// We refuse rsa keys smaller than 1024 bits.
	// test(nil, StatusPermerror, ErrWeakKey, func() {
	// 	key := getWeakRSAKey(t)
	// 	record.Key = "rsa"
	// 	record.PublicKey = key.Public()
	// 	txt, err := record.Record()
	// 	if err != nil {
	// 		t.Fatalf("making dns txt record: %s", err)
	// 	}
	// 	resolver.TXT = map[string][]string{
	// 		"test._domainkey.mox.example.": {txt},
	// 	}
	// 	sel.PrivateKey = key
	// 	selectors = []Selector{sel}
	// })
	// Key not allowed for email by DNS record. ../rfc/6376:1541
	test(nil, StatusPermerror, ErrKeyNotForEmail, func() {
		recordTxt += ";s=other"
		resolver.TXT = map[string][]string{
			"test._domainkey.mox.example.": {recordTxt},
		}
	})
	// todo: Record has flag "s" but identity does not have exact domain match. Cannot currently easily implement this test because Sign() always uses the same domain. ../rfc/6376:1575
	// Wrong signature, different datahash, and thus signature.
	test(nil, StatusFail, ErrSigVerify, func() {
		sign()
		msg = strings.ReplaceAll(msg, "Subject: test\r\n", "Subject: modified header\r\n")
	})
	// Signature is correct for bodyhash, but the body has changed.
	test(nil, StatusFail, ErrBodyhashMismatch, func() {
		sign()
		msg = strings.ReplaceAll(msg, "\r\ntest\r\n", "\r\nmodified body\r\n")
	})

	// Check that last-occurring header field is used.
	test(nil, StatusFail, ErrSigVerify, func() {
		sel.SealHeaders = false
		selectors = []Selector{sel}
		sign()
		msg = strings.ReplaceAll(msg, "\r\n\r\n", "\r\nsubject: another\r\n\r\n")
	})
	test(nil, StatusPass, nil, func() {
		sel.SealHeaders = false
		selectors = []Selector{sel}
		sign()
		msg = "subject: another\r\n" + msg
	})
}

func TestBodyHash(t *testing.T) {
	simpleGot, err := BodyHash(crypto.SHA256.New(), true, bufio.NewReader(strings.NewReader("")))
	if err != nil {
		t.Fatalf("body hash, simple, empty string: %s", err)
	}
	simpleWant := base64Decode("frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=")
	if !bytes.Equal(simpleGot, simpleWant) {
		t.Fatalf("simple body hash for empty string, got %s, expected %s", base64Encode(simpleGot), base64Encode(simpleWant))
	}

	relaxedGot, err := BodyHash(crypto.SHA256.New(), false, bufio.NewReader(strings.NewReader("")))
	if err != nil {
		t.Fatalf("body hash, relaxed, empty string: %s", err)
	}
	relaxedWant := base64Decode("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")
	if !bytes.Equal(relaxedGot, relaxedWant) {
		t.Fatalf("relaxed body hash for empty string, got %s, expected %s", base64Encode(relaxedGot), base64Encode(relaxedWant))
	}

	compare := func(a, b []byte) {
		t.Helper()
		if !bytes.Equal(a, b) {
			t.Fatalf("hash not equal")
		}
	}

	// NOTE: the trailing space in the strings below are part of the test for canonicalization.

	// ../rfc/6376:936
	exampleIn := strings.ReplaceAll(` c
d 	 e


`, "\n", "\r\n")
	relaxedOut := strings.ReplaceAll(` c
d e
`, "\n", "\r\n")
	relaxedBh, err := BodyHash(crypto.SHA256.New(), false, bufio.NewReader(strings.NewReader(exampleIn)))
	if err != nil {
		t.Fatalf("bodyhash: %s", err)
	}
	relaxedOutHash := sha256.Sum256([]byte(relaxedOut))
	compare(relaxedBh, relaxedOutHash[:])

	simpleOut := strings.ReplaceAll(` c
d 	 e
`, "\n", "\r\n")
	simpleBh, err := BodyHash(crypto.SHA256.New(), true, bufio.NewReader(strings.NewReader(exampleIn)))
	if err != nil {
		t.Fatalf("bodyhash: %s", err)
	}
	simpleOutHash := sha256.Sum256([]byte(simpleOut))
	compare(simpleBh, simpleOutHash[:])

	// ../rfc/8463:343
	relaxedBody := strings.ReplaceAll(`Hi.

We lost the game.  Are you hungry yet?

Joe.

`, "\n", "\r\n")
	relaxedGot, err = BodyHash(crypto.SHA256.New(), false, bufio.NewReader(strings.NewReader(relaxedBody)))
	if err != nil {
		t.Fatalf("body hash, relaxed, ed25519 example: %s", err)
	}
	relaxedWant = base64Decode("2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=")
	if !bytes.Equal(relaxedGot, relaxedWant) {
		t.Fatalf("relaxed body hash for ed25519 example, got %s, expected %s", base64Encode(relaxedGot), base64Encode(relaxedWant))
	}
}

func base64Decode(s string) []byte {
	buf, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return buf
}

func base64Encode(buf []byte) string {
	return base64.StdEncoding.EncodeToString(buf)
}
