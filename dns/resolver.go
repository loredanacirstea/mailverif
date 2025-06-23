package dns

type Result struct {
	// Authentic indicates whether the response was DNSSEC-signed and verified.
	// This package is a security-aware non-validating stub-resolver, sending requests
	// with the "authentic data" bit set to its recursive resolvers, but only if the
	// resolvers are trusted. Resolvers are trusted either if explicitly marked with
	// "options trust-ad" in /etc/resolv.conf, or if all resolver IP addresses are
	// loopback IP's. If the response from the resolver has the "authentic data" bit
	// set, the DNS name and all indirections towards the name, were signed and the
	// recursive resolver has verified them.
	Authentic bool
}

type Resolver interface {
	LookupTXT(name string) ([]string, Result, error)
}

type DNSError struct {
	UnwrapErr   error  // error returned by the [DNSError.Unwrap] method, might be nil
	Err         string // description of the error
	Name        string // name looked for
	Server      string // server used
	IsTimeout   bool   // if true, timed out; not all timeouts set this
	IsTemporary bool   // if true, error is temporary; not all errors set this

	// IsNotFound is set to true when the requested name does not
	// contain any records of the requested type (data not found),
	// or the name itself was not found (NXDOMAIN).
	IsNotFound bool
}

// Unwrap returns e.UnwrapErr.
func (e *DNSError) Unwrap() error { return e.UnwrapErr }

func (e *DNSError) Error() string {
	if e == nil {
		return "<nil>"
	}
	s := "lookup " + e.Name
	if e.Server != "" {
		s += " on " + e.Server
	}
	s += ": " + e.Err
	return s
}

// Timeout reports whether the DNS lookup is known to have timed out.
// This is not always known; a DNS lookup may fail due to a timeout
// and return a DNSError for which Timeout returns false.
func (e *DNSError) Timeout() bool { return e.IsTimeout }

// Temporary reports whether the DNS error is known to be temporary.
// This is not always known; a DNS lookup may fail due to a temporary
// error and return a DNSError for which Temporary returns false.
func (e *DNSError) Temporary() bool { return e.IsTimeout || e.IsTemporary }
