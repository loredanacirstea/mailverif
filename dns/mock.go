package dns

import (
	"slices"
)

// MockResolver is a Resolver used for testing.
// Set DNS records in the fields, which map FQDNs (with trailing dot) to values.
type MockResolver struct {
	TXT          map[string][]string
	CNAME        map[string]string
	Fail         []string // Records of the form "type name", e.g. "cname localhost." that will return a servfail.
	AllAuthentic bool     // Default value for authentic in responses. Overridden with Authentic and Inauthentic
	Authentic    []string // Like Fail, but records that cause the response to be authentic.
	Inauthentic  []string // Like Authentic, but making response inauthentic.
}

type mockReq struct {
	Type string // E.g. "cname", "txt", "mx", "ptr", etc.
	Name string // Name of request. For TLSA, the full requested DNS name, e.g. _25._tcp.<host>.
}

func (mr mockReq) String() string {
	return mr.Type + " " + mr.Name
}

var _ Resolver = MockResolver{}

func (r MockResolver) result(mr mockReq) (string, Result, error) {
	result := Result{Authentic: r.AllAuthentic}

	updateAuthentic := func(mock string) {
		if slices.Contains(r.Authentic, mock) {
			result.Authentic = true
		}
		if slices.Contains(r.Inauthentic, mock) {
			result.Authentic = false
		}
	}

	for {
		if slices.Contains(r.Fail, mr.String()) {
			updateAuthentic(mr.String())
			return mr.Name, Result{}, r.servfail(mr.Name)
		}

		cname, ok := r.CNAME[mr.Name]
		if !ok {
			updateAuthentic(mr.String())
			break
		}
		updateAuthentic("cname " + mr.Name)
		if mr.Type == "cname" {
			return mr.Name, result, nil
		}
		mr.Name = cname
	}
	return mr.Name, result, nil
}

func (r MockResolver) nxdomain(s string) error {
	return &DNSError{
		Err:        "no record",
		Name:       s,
		Server:     "mock",
		IsNotFound: true,
	}
}

func (r MockResolver) servfail(s string) error {
	return &DNSError{
		Err:         "temp error",
		Name:        s,
		Server:      "mock",
		IsTemporary: true,
	}
}

func (r MockResolver) LookupTXT(name string) ([]string, Result, error) {
	mr := mockReq{"txt", name}
	name, result, err := r.result(mr)
	if err != nil {
		return nil, result, err
	}
	l, ok := r.TXT[name]
	if !ok {
		return nil, result, r.nxdomain(name)
	}
	return l, result, nil
}
