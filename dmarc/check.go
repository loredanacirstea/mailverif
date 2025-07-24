package dmarc

import (
	"strings"
)

// 1. Check DKIM: Was there a valid DKIM signature from example.com?
// 2. Check SPF: Did SPF pass for the envelope sender domain?
// 3. Check alignment: Do the From: domain, DKIM domain, and SPF envelope domain match?
// If alignment + one of SPF or DKIM passes → DMARC passes
func CheckDMARC(domain string, dmarcRecord *Record, spf AuthResult, dkim []AuthResult, dkimpass bool) (bool, bool) {
	if dmarcRecord == nil {
		return false, dkimpass // No policy available
	}

	spfAligned := false
	if spf.Valid {
		if dmarcRecord.SPFAlignment == AlignmentStrict {
			spfAligned = strings.EqualFold(spf.Domain, domain)
		} else {
			spfAligned = isSubdomain(spf.Domain, domain)
		}
	}

	dkimAligned := false
	for _, v := range dkim {
		if v.Valid {
			if dmarcRecord.DKIMAlignment == AlignmentStrict {
				dkimAligned = strings.EqualFold(v.Domain, domain)
			} else {
				dkimAligned = isSubdomain(v.Domain, domain)
			}
			if dkimAligned {
				break
			}
		}
	}

	// At least one aligned result must pass
	return spfAligned || dkimAligned, dkimAligned
}

// returns true if child is equal to or subdomain of parent
func isSubdomain(child, parent string) bool {
	child = strings.ToLower(child)
	parent = strings.ToLower(parent)
	return child == parent || strings.HasSuffix(child, "."+parent)
}
