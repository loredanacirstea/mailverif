package publicsuffix_test

import (
	"fmt"
	"log/slog"

	"github.com/loredanacirstea/mailverif/dns"
	"github.com/loredanacirstea/mailverif/publicsuffix"
)

func ExampleLookup() {
	// Lookup the organizational domain for sub.example.org.
	orgDom := publicsuffix.Lookup(slog.Default(), dns.Domain{ASCII: "sub.example.org"})
	fmt.Println(orgDom)
	// Output: example.org
}
