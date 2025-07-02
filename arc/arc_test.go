package arc

import (
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	samples "github.com/loredanacirstea/mailverif/_samples"
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

func TestVerifyARC(t *testing.T) {
	pkglog := slog.New(slog.NewTextHandler(os.Stdout, nil))
	msgr := strings.NewReader(samples.EmailARC1)

	results, err := Verify(pkglog, &DNSResolverTest{}, false, msgr, false, true, timeNow, nil)
	require.NoError(t, err)
	require.NoError(t, results.Result.Err)
	require.Equal(t, dkim.StatusPass, results.Result.Status)
	require.Equal(t, 1, len(results.Chain))
	for i, v := range results.Chain {
		require.Equal(t, i+1, v.Instance)
		require.Equal(t, dkim.StatusPass, v.Dkim)
		require.Equal(t, dkim.StatusPass, v.Dmarc)
		require.Equal(t, dkim.StatusPass, v.Spf)
		require.Equal(t, dkim.StatusNone, v.CV)
		require.True(t, v.AMSValid)
		require.True(t, v.ASValid)
	}

	msgr = strings.NewReader(samples.EmailARC3)
	results, err = Verify(pkglog, &DNSResolverTest{}, false, msgr, false, true, timeNow, nil)
	require.NoError(t, err)
	require.NoError(t, results.Result.Err)
	require.Equal(t, dkim.StatusPass, results.Result.Status)
	require.Equal(t, 3, len(results.Chain))
	for i, v := range results.Chain {
		require.Equal(t, i+1, v.Instance)
		require.Equal(t, dkim.StatusPass, v.Dkim)
		require.Equal(t, dkim.StatusPass, v.Dmarc)
		require.Equal(t, dkim.StatusPass, v.Spf)
		if i == 0 {
			require.Equal(t, dkim.StatusNone, v.CV)
		} else {
			require.Equal(t, dkim.StatusPass, v.CV)
		}
		require.True(t, v.AMSValid)
		require.True(t, v.ASValid)
	}
}

func TestSignARC(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	r := strings.NewReader(signedMailString)
	// ed25519Key := ed25519.NewKeyFromSeed(make([]byte, 32))
	rsaKey := testutils.GetRSAKey(t)
	resolver := &DNSResolverTest{}
	publicKey := &dkim.Record{
		Version:   "DKIM1",
		Key:       "rsa",
		Hashes:    []string{"sha256"},
		Services:  []string{"email"},
		PublicKey: &rsaKey.PublicKey,
		Pubkey:    rsaKey.PublicKey.N.Bytes(),
	}

	domain := dns.Domain{ASCII: "example.org"}
	sel := dkim.Selector{
		Hash:       "sha256",
		PrivateKey: rsaKey,
		Domain:     dns.Domain{ASCII: "brisbane"},
	}
	selectors := []dkim.Selector{sel}
	mailfrom := "joe@football.example.com"
	ipfrom := "85.215.130.119"
	mailServerDomain := "example.org"
	header, err := Sign(logger, resolver, domain, selectors, false, r, mailfrom, ipfrom, mailServerDomain, false, true, timeNow, publicKey)
	require.NoError(t, err)

	slices.Reverse(header)
	newemail := utils.SerializeHeaders(header) + signedMailString

	// fmt.Println(newemail)

	msgr := strings.NewReader(newemail)
	results, err := Verify(logger, resolver, false, msgr, false, true, timeNow, publicKey)
	require.NoError(t, err)
	require.NoError(t, results.Result.Err)
	require.Equal(t, dkim.StatusPass, results.Result.Status)
	require.Equal(t, 1, len(results.Chain))
	for i, v := range results.Chain {
		require.Equal(t, i+1, v.Instance)
		require.Equal(t, dkim.StatusPass, v.Dkim)
		require.Equal(t, dkim.StatusPass, v.Dmarc)
		require.Equal(t, dkim.StatusPass, v.Spf)
		require.Equal(t, dkim.StatusNone, v.CV)
		require.True(t, v.AMSValid)
		require.True(t, v.ASValid)
	}
}

type DNSResolverTest struct{}

func (r *DNSResolverTest) LookupTXT(name string) ([]string, dns.Result, error) {
	res, err := net.LookupTXT(name)
	return res, dns.Result{Authentic: true}, err
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
