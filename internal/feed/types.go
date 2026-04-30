package feed

import "time"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityNone     Severity = "none"
	SeverityUnknown  Severity = "unknown"
)

const (
	SourceCISAKEV = "cisa-kev"
	SourceNVD     = "nvd"
)

type CVERecord struct {
	CVEID             string
	Title             string
	Description       string
	Severity          Severity
	CVSSScore         *float64
	PublishedAt       *time.Time
	ModifiedAt        *time.Time
	Rejected          bool
	KnownExploited    bool
	KEVDueDate        *time.Time
	KEVVendorProject  string
	KEVProduct        string
	KEVRequiredAction string
	Source            string
	MetadataJSON      []byte
}

type SourceResult struct {
	Source  string
	Records int
	Error   string
}
