package arc

import (
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	samples "github.com/loredanacirstea/mailverif/_samples"
	"github.com/loredanacirstea/mailverif/dkim"
	"github.com/loredanacirstea/mailverif/dns"
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

type DNSResolverTest struct{}

func (r *DNSResolverTest) LookupTXT(name string) ([]string, dns.Result, error) {
	res, err := net.LookupTXT(name)
	return res, dns.Result{Authentic: true}, err
}
