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
	SourceAlpineSecDB        = "alpine-secdb"
	SourceCISAKEV            = "cisa-kev"
	SourceDebianTracker      = "debian-tracker"
	SourceNVD                = "nvd"
	SourceRedHatSecurityData = "redhat-security-data"
	SourceUbuntuOSV          = "ubuntu-osv"
)

type FetchResult struct {
	Records          []CVERecord
	AffectedPackages []AffectedPackage
}

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

type AffectedPackage struct {
	CVEID             string
	Source            string
	DistroID          string
	DistroVersionID   string
	DistroCodename    string
	PackageName       string
	SourcePackageName string
	FixedVersion      string
	AffectedVersions  []string
	Repository        string
	Severity          Severity
	PackageState      string
	MetadataJSON      []byte
}

type SourceResult struct {
	Source  string
	Records int
	Error   string
}
