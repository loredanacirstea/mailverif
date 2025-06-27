package samples

import (
	_ "embed"
)

var (
	//go:embed email_arc1.eml
	EmailARC1 string

	//go:embed email_arc3.eml
	EmailARC3 string
)
