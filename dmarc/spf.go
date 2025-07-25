package dmarc

import (
	"errors"
	"net"
	"strings"

	"github.com/loredanacirstea/mailverif/dns"
)

// TxtLookupFunc is a DNS TXT record lookup function.
type TxtLookupFunc func(domain string) ([]string, dns.Result, error)

// AuthResult represents a basic SPF check result.
type AuthResult struct {
	Domain string
	Valid  bool
}

// CheckSPF checks SPF validity for a given MAIL FROM domain and sender IP.
// This function performs a basic SPF check (no full RFC 7208 compliance).
func CheckSPF(domain string, ip string, lookupTxt TxtLookupFunc) (AuthResult, error) {
	txts, _, err := lookupTxt(domain)
	if err != nil {
		return AuthResult{Domain: domain, Valid: false}, err
	}

	var spfRecord string
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=spf1 ") {
			spfRecord = txt
			break
		}
	}

	if spfRecord == "" {
		return AuthResult{Domain: domain, Valid: false}, errors.New("no SPF record found")
	}

	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return AuthResult{Domain: domain, Valid: false}, errors.New("invalid IP")
	}

	// Evaluate SPF mechanisms (basic support for ip4/ip6)
	mechs := strings.Fields(spfRecord)[1:]
	for _, mech := range mechs {
		mech = strings.TrimPrefix(mech, "+") // explicit pass

		if strings.HasPrefix(mech, "ip4:") && ipAddr.To4() != nil {
			cidr := strings.TrimPrefix(mech, "ip4:")
			if !strings.Contains(cidr, "/") {
				cidr += "/32" // default for ip4: only this IP is valid
			}
			if _, ipnet, err := net.ParseCIDR(cidr); err == nil && ipnet.Contains(ipAddr) {
				return AuthResult{Domain: domain, Valid: true}, nil
			}
		}

		if strings.HasPrefix(mech, "ip6:") && ipAddr.To16() != nil && ipAddr.To4() == nil {
			cidr := strings.TrimPrefix(mech, "ip6:")
			if !strings.Contains(cidr, "/") {
				cidr += "/128" // default for ip6: only this IP is valid
			}
			if _, ipnet, err := net.ParseCIDR(cidr); err == nil && ipnet.Contains(ipAddr) {
				return AuthResult{Domain: domain, Valid: true}, nil
			}
		}

		// (Optional) Handle include: recursively
		if strings.HasPrefix(mech, "include:") {
			inclDomain := strings.TrimPrefix(mech, "include:")
			result, err := CheckSPF(inclDomain, ip, lookupTxt)
			if err != nil {
				return AuthResult{Domain: domain, Valid: result.Valid}, err
			}
			if result.Valid {
				return AuthResult{Domain: domain, Valid: true}, nil
			}
		}
	}

	// Default to fail
	return AuthResult{Domain: domain, Valid: false}, nil
}
