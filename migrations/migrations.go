package migrations

import "embed"

// Files contains the ordered SQL migrations for CT-CVE.
//
//go:embed *.sql
var Files embed.FS
