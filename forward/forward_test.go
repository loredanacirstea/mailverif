package forward

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/mail"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	testutils "github.com/loredanacirstea/mailverif/_testutils"
	"github.com/loredanacirstea/mailverif/dkim"
	"github.com/loredanacirstea/mailverif/dns"
	utils "github.com/loredanacirstea/mailverif/utils"
)

var timeNow = time.Now

func init() {
	timeNow = func() time.Time {
		return time.Unix(424242, 0)
	}
}

func TestSignForward(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	initialEmail := mailString
	rsaKey := testutils.GetRSAKey(t)
	recordOrig := &dkim.Record{
		Version:   "DKIM1",
		Key:       "rsa",
		Hashes:    []string{"sha256"},
		Services:  []string{"email"},
		PublicKey: &testPrivateKey.PublicKey,
		Flags:     []string{"s"},
	}
	record := &dkim.Record{
		Version:   "DKIM1",
		Key:       "rsa",
		Hashes:    []string{"sha256"},
		Services:  []string{"email"},
		PublicKey: &rsaKey.PublicKey,
		Flags:     []string{"s"},
	}
	domain := dns.Domain{ASCII: "football.example.com"}
	sel := dkim.Selector{
		Hash:       "sha256",
		PrivateKey: rsaKey,
		Domain:     dns.Domain{ASCII: "brisbane"},
	}
	selectors := []dkim.Selector{sel}
	mailfrom := "joe@football.example.com"
	ipfrom := "192.168.1.1"

	txtOrig, err := recordOrig.Record()
	if err != nil {
		t.Fatalf("making dns txt record: %s", err)
	}
	resolver := dns.MockResolver{
		TXT: map[string][]string{
			// DMARC
			"_dmarc.brisbane.example.com": {"v=DMARC1;p=reject;rua=mailto:dmarc-reports@brisbane.example.com!10m"},
			"_dmarc.football.example.com": {"v=DMARC1;p=reject;rua=mailto:dmarc-reports@football.example.com!10m"},

			// SPF
			"football.example.com": {fmt.Sprintf("v=spf1 ip4:%s -all", ipfrom)},

			// DKIM
			"brisbane._domainkey.football.example.com.": {txtOrig},
			"brisbane._domainkey.example.com.":          {txtOrig},
		},
	}
	dkimSel := dkim.Selector{
		Hash:       "sha256",
		PrivateKey: testPrivateKey,
		Domain:     dns.Domain{ASCII: "brisbane"},

		Headers:     strings.Split("From,To,Cc,Bcc,Reply-To,Subject,Date", ","),
		SealHeaders: true,
	}

	// sign initial email dkim
	dkimH, err := dkim.Sign2(logger, "joe", domain, []dkim.Selector{dkimSel}, false, []byte(initialEmail), timeNow)
	require.NoError(t, err)

	// compute new email
	initialEmail = utils.SerializeHeaders(dkimH) + initialEmail

	from := &mail.Address{Name: "My Name", Address: "myaddress@football.example.com"}
	to := []*mail.Address{{Name: "Some Name", Address: "someaddress@football.example.com"}}
	subjectAddl := "additional subject"
	timestamp := time.Date(2025, time.July, 10, 10, 3, 0, 0, time.UTC)
	var newemail string

	// verify original DKIM signature
	resultsDkim, err := dkim.Verify2(logger, resolver, false, dkim.DefaultPolicy, []byte(initialEmail), true, false, true, timeNow, recordOrig)
	require.NoError(t, err)
	require.Equal(t, 1, len(resultsDkim))
	require.NoError(t, resultsDkim[0].Err)
	require.Equal(t, dkim.StatusPass, resultsDkim[0].Status)

	// prepare forwarded email & add forward headers
	header, br, err := Forward(logger, resolver, domain, selectors, false, []byte(initialEmail), mailfrom, ipfrom, from, to, nil, nil, subjectAddl, timestamp, generateMessageId(), false, true, timeNow, record)
	require.NoError(t, err)

	bodyBytes, err := io.ReadAll(br)
	require.NoError(t, err)

	// also add dkim signature for this instance
	dkimHeaders, err := dkim.Sign(logger, "myaddress", domain, []dkim.Selector{dkimSel}, false, header, bufio.NewReader(bytes.NewReader(bodyBytes)), timeNow)
	require.NoError(t, err)
	header = append(dkimHeaders, header...)

	// compute new email
	newemail = utils.SerializeHeaders(header) + "\r\n" + string(bodyBytes)

	results, err := Verify(logger, resolver, false, []byte(newemail), false, true, timeNow, record)
	require.NoError(t, err)
	require.NoError(t, results.Result.Err)
	require.Equal(t, dkim.StatusPass, results.Result.Status)
	require.Equal(t, 1, len(results.Chain))
	for i, v := range results.Chain {
		require.Equal(t, i+1, v.Instance)
		require.True(t, v.ChainSigValid)
		require.True(t, v.ChainSealValid)
		require.Equal(t, dkim.StatusPass, v.DkimSource)
		require.Equal(t, dkim.StatusPass, v.Dmarc)
		require.Equal(t, dkim.StatusPass, v.Spf)
		require.Equal(t, dkim.StatusNone, v.CV)
		require.Equal(t, dkim.StatusPass, v.Dkim)
	}

	// i=2
	mailfrom = "myaddress@football.example.com"
	from = &mail.Address{Name: "Some Name", Address: "someaddress@football.example.com"}
	to = []*mail.Address{{Name: "Some Name2", Address: "someaddress2@football.example.com"}}
	subjectAddl = "additional subject2"
	timestamp = time.Date(2025, time.July, 11, 10, 3, 0, 0, time.UTC)
	// prepare forwarded email & add forward headers
	header, br, err = Forward(logger, resolver, domain, selectors, false, []byte(newemail), mailfrom, ipfrom, from, to, nil, nil, subjectAddl, timestamp, generateMessageId(), false, true, timeNow, record)
	require.NoError(t, err)

	bodyBytes, err = io.ReadAll(br)
	require.NoError(t, err)

	// also add dkim signature for this instance
	dkimHeaders, err = dkim.Sign(logger, "someaddress", domain, []dkim.Selector{dkimSel}, false, header, bufio.NewReader(bytes.NewReader(bodyBytes)), timeNow)
	require.NoError(t, err)
	header = append(dkimHeaders, header...)
	newemail = utils.SerializeHeaders(header) + "\r\n" + string(bodyBytes)

	results, err = Verify(logger, resolver, false, []byte(newemail), false, true, timeNow, record)
	require.NoError(t, err)
	require.NoError(t, results.Result.Err)
	require.Equal(t, dkim.StatusPass, results.Result.Status)
	require.Equal(t, 2, len(results.Chain))
	for i, v := range results.Chain {
		require.Equal(t, i+1, v.Instance)
		require.True(t, v.ChainSigValid)
		require.True(t, v.ChainSealValid)
		require.Equal(t, dkim.StatusPass, v.DkimSource)
		require.Equal(t, dkim.StatusPass, v.Dmarc)
		require.Equal(t, dkim.StatusPass, v.Spf)
		if i == 0 {
			require.Equal(t, dkim.StatusNone, v.CV)
		} else {
			require.Equal(t, dkim.StatusPass, v.CV)
		}
		require.Equal(t, dkim.StatusPass, v.Dkim)
	}

	// i=3
	mailfrom = "someaddress@football.example.com"
	from = &mail.Address{Name: "Some Name2", Address: "someaddress2@football.example.com"}
	to = []*mail.Address{{Name: "Some Name3", Address: "someaddress3@football.example.com"}}
	subjectAddl = "additional subject3"
	timestamp = time.Date(2025, time.July, 12, 10, 3, 0, 0, time.UTC)
	// prepare forwarded email & add forward headers
	header, br, err = Forward(logger, resolver, domain, selectors, false, []byte(newemail), mailfrom, ipfrom, from, to, nil, nil, subjectAddl, timestamp, generateMessageId(), false, true, timeNow, record)
	require.NoError(t, err)

	bodyBytes, err = io.ReadAll(br)
	require.NoError(t, err)

	// also add dkim signature for this instance
	dkimHeaders, err = dkim.Sign(logger, "someaddress2", domain, []dkim.Selector{dkimSel}, false, header, bufio.NewReader(bytes.NewReader(bodyBytes)), timeNow)
	require.NoError(t, err)
	header = append(dkimHeaders, header...)

	newemail = utils.SerializeHeaders(header) + "\r\n" + string(bodyBytes)

	results, err = Verify(logger, resolver, false, []byte(newemail), false, true, timeNow, record)
	require.NoError(t, err)
	require.NoError(t, results.Result.Err)
	require.Equal(t, dkim.StatusPass, results.Result.Status)
	require.Equal(t, 3, len(results.Chain))
	for i, v := range results.Chain {
		require.Equal(t, i+1, v.Instance)
		require.True(t, v.ChainSigValid)
		require.True(t, v.ChainSealValid)
		require.Equal(t, dkim.StatusPass, v.DkimSource)
		require.Equal(t, dkim.StatusPass, v.Dmarc)
		require.Equal(t, dkim.StatusPass, v.Spf)
		if i == 0 {
			require.Equal(t, dkim.StatusNone, v.CV)
		} else {
			require.Equal(t, dkim.StatusPass, v.CV)
		}
		require.Equal(t, dkim.StatusPass, v.Dkim)
	}
}

type DNSResolverTest struct{}

func (r *DNSResolverTest) LookupTXT(name string) ([]string, dns.Result, error) {
	res, err := net.LookupTXT(name)
	return res, dns.Result{Authentic: true}, err
}

func generateMessageId() string {
	v := time.Now().UnixNano()
	return fmt.Sprintf("%d.5F8J@football.example.com", v)
}

const mailHeaderString = "From: Joe SixPack <joe@football.example.com>\r\n" +
	"To: Suzie Q <suzie@shopping.example.net>\r\n" +
	"Subject: Is dinner ready?\r\n" +
	"Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n" +
	"Message-ID: <20030712040037.46341.5F8J@football.example.com>\r\n"

const mailBodyString = "Hi.\r\n" +
	"\r\n" +
	"We lost the game. Are you hungry yet?\r\n" +
	"\r\n" +
	"Joe."

const mailString = mailHeaderString + "\r\n" + mailBodyString

const signedMailString = "DKIM-Signature: a=rsa-sha256; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;" + "\r\n" +
	" " + "c=simple/simple; d=example.org; h=From:To:Subject:Date:Message-ID;" + "\r\n" +
	" " + "s=brisbane; t=424242; v=1;" + "\r\n" +
	" " + "b=MobyyDTeHhMhNJCEI6ATNK63ZQ7deSXK9umyzAvYwFqE6oGGvlQBQwqr1aC11hWpktjMLP1/" + "\r\n" +
	" " + "m0PBi9v7cRLKMXXBIv2O0B1mIWdZPqd9jveRJqKzCb7SpqH2u5kK6i2vZI639ENTQzRQdxSAGXc" + "\r\n" +
	" " + "PcPYjrgkqj7xklnrNBs0aIUA=" + "\r\n" +
	mailHeaderString +
	"\r\n" +
	mailBodyString

const signedARCMailString = "ARC-Authentication-Results: i=1; none" + "\r\n" +
	`ARC-Message-Signature: a=rsa-sha256; i=1 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 c=simple/simple; d=example.org;
 h=DKIM-Signature:From:To:Subject:Date:Message-ID; s=brisbane; t=424242;
 v=1;
 b=kzuq0Ln2l3035rhJQRBzcz1607AmyyBZeMyZaBJ2OcXJA0zwFEv8AMzV6TYwQF9YMcmN5Xah
 DE2PxusJXdenQFTc0Hy9VZ3OzO+fwyCpuZwf5hM+004hl48sRtAeSlRsU13Nfitau2cuNaMH1j2
 RWHzYTMqtDCg6U3MJpbNxDQ4=` + "\r\n" + `ARC-Seal: i=1; a=rsa-sha256; d=example.org; s=brisbane; t=424242; cv=pass; b=DFcsBtLdyGV4cl1vsfiJXNXaHQb9ho1igPXugcMvU1EPYSD2w8rkQ/blQscV1AXTJbdjkp3eHKataSCOwYX/YOfcqsfhJ7lzi/NLjXE3F8sHFMKt7S9BpVQzaprKRz3KXMy2cyia7D4AwgW9cuW5fizdg2TlrAke36QBI1hSGZg=` + "\r\n" + signedMailString

// const toForwardEmailString = “ + "\r\n" + signedMailString
// const toForwardEmailString = signedMailString

// const toForwardEmailString = mailHeaderString + "\r\n" + mailBodyString

const testPrivateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIICXwIBAAKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFC
jxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gb
to/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB
AoGBALmn+XwWk7akvkUlqb+dOxyLB9i5VBVfje89Teolwc9YJT36BGN/l4e0l6QX
/1//6DWUTB3KI6wFcm7TWJcxbS0tcKZX7FsJvUz1SbQnkS54DJck1EZO/BLa5ckJ
gAYIaqlA9C0ZwM6i58lLlPadX/rtHb7pWzeNcZHjKrjM461ZAkEA+itss2nRlmyO
n1/5yDyCluST4dQfO8kAB3toSEVc7DeFeDhnC1mZdjASZNvdHS4gbLIA1hUGEF9m
3hKsGUMMPwJBAPW5v/U+AWTADFCS22t72NUurgzeAbzb1HWMqO4y4+9Hpjk5wvL/
eVYizyuce3/fGke7aRYw/ADKygMJdW8H/OcCQQDz5OQb4j2QDpPZc0Nc4QlbvMsj
7p7otWRO5xRa6SzXqqV3+F0VpqvDmshEBkoCydaYwc2o6WQ5EBmExeV8124XAkEA
qZzGsIxVP+sEVRWZmW6KNFSdVUpk3qzK0Tz/WjQMe5z0UunY9Ax9/4PVhp/j61bf
eAYXunajbBSOLlx4D+TunwJBANkPI5S9iylsbLs6NkaMHV6k5ioHBBmgCak95JGX
GMot/L2x0IYyMLAz6oLWh2hm7zwtb0CgOrPo1ke44hFYnfc=
-----END RSA PRIVATE KEY-----
`

const testEd25519SeedBase64 = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A="

var (
	testPrivateKey        *rsa.PrivateKey
	testEd25519PrivateKey ed25519.PrivateKey
)

func init() {
	block, _ := pem.Decode([]byte(testPrivateKeyPEM))
	var err error
	testPrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	ed25519Seed, err := base64.StdEncoding.DecodeString(testEd25519SeedBase64)
	if err != nil {
		panic(err)
	}
	testEd25519PrivateKey = ed25519.NewKeyFromSeed(ed25519Seed)
}
