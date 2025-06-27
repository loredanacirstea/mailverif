package testutils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func GetRSAKey(t *testing.T) *rsa.PrivateKey {
	// Generated with:
	// openssl genrsa -out pkcs1.pem 2048
	// openssl pkcs8 -topk8 -inform pem -in pkcs1.pem -outform pem -nocrypt -out pkcs8.pem
	const rsaText = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCu7iTF/AAvJQ3U
WRlcXd+n6HXOSYvmDlqjLsuCKn6/T+Ma0ZtobCRfzyXh5pFQBCHffW6fpEzJs/2o
+e896zb1QKjD8Xxsjarjdw1iXzgMj/lhDGWyNyUHC34+k77UfpQBZgPLvZHyYyQG
sVMzzmvURE+GMFmXYUiGI581PdCx4bNba/4gYQnc/eqQ8oX0T//2RdRqdhdDM2d7
CYALtkxKetH1F+Rz7XDjFmI3GjPs1KwVdh+Cl8kejThi0SVxXpqnoqB2WGsr/lGG
GxsxcpLb/+KWFjI0go3OJjMaxFCmhB0pGdW8I7kNwNrZsCdSvmjMDojNuegx6WMg
/T7go3CvAgMBAAECggEAQA3AlmSDtr+lNDvZ7voKwwN6W6qPmRJpevZQG54u4iPA
/5mAA/kRSqnh77mLPRb+RkU6RCeX3IXVXNIEGhKugZiHE5Sx4FfxmrAFzR8buXHg
uXoeJOdPXiiFtilIh6u/y1FNE4YbUnud/fthgYdU8Zl/2x2KOMWtFj0l94tmhzOI
b2y8/U8r85anI5XGYuzRCqKS1WskXhkXH8LZUB+9yAxX7V5ysgxjofM4FW8ns7yj
K4cBS8KY2v3t7TZ4FgwkAhPcTfBc/E2UWT1Ztmr+18LFV5bqI8g2YlN+BgCxU7U/
1tawxqFhs+xowEpzNwAvjAIPpptIRiY1rz7sBB9g5QKBgQDLo/5rTUwNOPR9dYvA
+DYUSCfxvNamI4GI66AgwOeN8O+W+dRDF/Ewbk/SJsBPSLIYzEiQ2uYKcNEmIjo+
7WwSCJZjKujovw77s9JAHexhpd8uLD2w9l3KeTg41LEYm2uVwoXWEHYSYJ9Ynz0M
PWxvi2Hm0IoQ7gJIfxng/wIw3QKBgQDb6GFvPH/OTs40+dopwtm3irmkBAmT8N0b
3TpehONCOiL4GPxmn2DN6ELhHFV27Jj/1CfpGVbcBlaS1xYUGUGsB9gYukhdaBST
KGHRoeZDcf0gaQLKG15EEfFOvcKI9aGljV8FdFfG+Z4fW3LA8khvpvjLLkv1A1jM
MrEBthco+wKBgD45EM9GohtUMNh450gCT7voxFPICKphJP5qSNZZOyeS3BJ8qdAK
a8cJndgvwQk4xDpxiSbBzBKaoD2Prc52i1QDTbhlbx9W6cQdEPxIaGb54PThzcPZ
s5Tfbz9mNeq36qqq8mwTQZCh926D0YqA5jY7F6IITHeZ0hbGx2iJYuj9AoGARIyK
ms8kE95y3wanX+8ySMmAlsT/a1NgyUfL4xzPbpyKvAWl4CN8XJMzDdL0PS8BfnXW
vw28CrgbEojjg/5ff02uqf6fgiZoi3rCC0PJcGq++fRh/zhKyTNCokX6txDCg8Wu
wheDKS40gRfTjJu5wrwsv8E9wjF546VFkf/99jMCgYEAm/x+kEfWKuzx8pQT66TY
pxnC41upJOO1htTHNIN24J7XrrFI5+OZq90G+t/VgWX08Z8RlhejX+ukBf+SRu3u
5VMGcAs4px+iECX/FHo21YQFnrmArN1zdFxPU3rBWoBueqmGO6FT0HBbKzTuS7N0
7fIv3GQqImz3+ZbYWlXfkPI=
-----END PRIVATE KEY-----`
	return ParseRSAKey(t, rsaText)
}

func ParseRSAKey(t *testing.T, rsaText string) *rsa.PrivateKey {
	rsab, _ := pem.Decode([]byte(rsaText))
	if rsab == nil {
		t.Fatalf("no pem in privKey")
	}

	key, err := x509.ParsePKCS8PrivateKey(rsab.Bytes)
	if err != nil {
		t.Fatalf("parsing private key: %s", err)
	}
	return key.(*rsa.PrivateKey)
}

func GetWeakRSAKey(t *testing.T) *rsa.PrivateKey {
	const rsaText = `-----BEGIN PRIVATE KEY-----
MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAsQo3ATJAZ4aAZz+l
ndXl27ODOY+49DjYxwhgtg+OU8A1WEYCfWaZ7ozYtpsqH8GNFvlKtK38eKbdDuLw
gsFYMQIDAQABAkBwstb2/P1Aqb9deoe8JOiw5eJYJySO2w0sDio6W0a4Cqi7XQ7r
/yZ1gOp+ZnShX/sJq0Pd16UkJUUEtEPoZyptAiEA4KLP8pz/9R0t7Envqph1oVjQ
CVDIL/UKRmdnMiwwDosCIQDJwiu08UgNNeliAygbkC2cdszjf4a3laGmYbfWrtAn
swIgUBfc+w0degDgadpm2LWpY1DuRBQIfIjrE/U0Z0A4FkcCIHxEuoLycjygziTu
aM/BWDac/cnKDIIbCbvfSEpU1iT9AiBsbkAcYCQ8mR77BX6gZKEc74nSce29gmR7
mtrKWknTDQ==
-----END PRIVATE KEY-----`
	return ParseRSAKey(t, rsaText)
}
