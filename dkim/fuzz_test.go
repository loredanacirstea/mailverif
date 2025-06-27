package dkim

import (
	"testing"

	utils "github.com/loredanacirstea/mailverif/utils"
)

func FuzzParseSignature(f *testing.F) {
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, buf []byte) {
		ParseSignature(&utils.Header{Key: DKIM_SIGNATURE_HEADER, Raw: buf}, false, DKIMSpec.RequiredTags, DKIMSpec.PolicyParsing, DKIMSpec.NewSigWithDefaults)
	})
}

func FuzzParseRecord(f *testing.F) {
	f.Add("")
	f.Add("v=DKIM1; p=bad")
	f.Fuzz(func(t *testing.T, s string) {
		r, _, err := ParseRecord(s)
		if err == nil {
			if _, err := r.Record(); err != nil {
				t.Errorf("r.Record() for parsed record %s, %#v: %s", s, r, err)
			}
		}
	})
}
