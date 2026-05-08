package ctops

import "time"

const ContractVersion = "2026-04-30"

type ServiceTokenScope string

const (
	ScopeInventoryWrite ServiceTokenScope = "inventory:write"
	ScopeFindingsWrite  ServiceTokenScope = "findings:write"
	ScopeConnectionRead ServiceTokenScope = "connection:read"
)

type ServiceToken struct {
	ID      string
	Secret  string
	OrgID   string
	Scopes  []ServiceTokenScope
	Revoked bool
}

type Connection struct {
	Name            string
	OrgID           string
	CTOpsBaseURL    string
	InventoryTokens []ServiceToken
	CTOpsToken      ServiceToken
}

type InventorySnapshot struct {
	ContractVersion string             `json:"contractVersion"`
	OrgID           string             `json:"orgId"`
	OrgSlug         string             `json:"orgSlug"`
	SnapshotID      string             `json:"snapshotId"`
	SnapshotType    string             `json:"snapshotType"`
	GeneratedAt     time.Time          `json:"generatedAt"`
	Cursor          *string            `json:"cursor"`
	Hosts           []InventoryHost    `json:"hosts"`
	Packages        []InventoryPackage `json:"packages"`
}

type InventoryHost struct {
	HostID      string     `json:"hostId"`
	AgentID     *string    `json:"agentId"`
	Hostname    string     `json:"hostname"`
	DisplayName *string    `json:"displayName"`
	OS          *string    `json:"os"`
	OSVersion   *string    `json:"osVersion"`
	Arch        *string    `json:"arch"`
	IPAddresses []string   `json:"ipAddresses"`
	Status      string     `json:"status"`
	LastSeenAt  *time.Time `json:"lastSeenAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
	DeletedAt   *time.Time `json:"deletedAt"`
}

type InventoryPackage struct {
	SoftwarePackageID string     `json:"softwarePackageId"`
	HostID            string     `json:"hostId"`
	Name              string     `json:"name"`
	Version           string     `json:"version"`
	Architecture      *string    `json:"architecture"`
	Source            string     `json:"source"`
	Fingerprint       string     `json:"fingerprint"`
	DistroID          *string    `json:"distroId"`
	DistroVersionID   *string    `json:"distroVersionId"`
	DistroCodename    *string    `json:"distroCodename"`
	DistroIDLike      []string   `json:"distroIdLike"`
	SourceName        *string    `json:"sourceName"`
	SourceVersion     *string    `json:"sourceVersion"`
	PackageEpoch      *string    `json:"packageEpoch"`
	PackageRelease    *string    `json:"packageRelease"`
	Repository        *string    `json:"repository"`
	Origin            *string    `json:"origin"`
	InstallDate       *time.Time `json:"installDate"`
	FirstSeenAt       time.Time  `json:"firstSeenAt"`
	LastSeenAt        time.Time  `json:"lastSeenAt"`
	RemovedAt         *time.Time `json:"removedAt"`
	DeletedAt         *time.Time `json:"deletedAt"`
}

type InventorySnapshotResult struct {
	Accepted         bool   `json:"accepted"`
	SnapshotID       string `json:"snapshotId"`
	HostsAccepted    int    `json:"hostsAccepted"`
	PackagesAccepted int    `json:"packagesAccepted"`
	RowsRejected     int    `json:"rowsRejected"`
	NextAction       string `json:"nextAction"`
}

type InventorySnapshotApplyResult struct {
	Response InventorySnapshotResult
	Findings []Finding
	Replayed bool
}

type FindingStatus string

const (
	FindingStatusOpen     FindingStatus = "open"
	FindingStatusResolved FindingStatus = "resolved"
)

type Finding struct {
	FindingID         string         `json:"findingId"`
	HostID            string         `json:"hostId"`
	SoftwarePackageID string         `json:"softwarePackageId"`
	CVEID             string         `json:"cveId"`
	Status            FindingStatus  `json:"status"`
	PackageName       string         `json:"packageName"`
	InstalledVersion  string         `json:"installedVersion"`
	FixedVersion      string         `json:"fixedVersion,omitempty"`
	Source            string         `json:"source"`
	Severity          string         `json:"severity"`
	CVSSScore         *float64       `json:"cvssScore"`
	KnownExploited    bool           `json:"knownExploited"`
	Confidence        string         `json:"confidence"`
	MatchReason       string         `json:"matchReason,omitempty"`
	FirstSeenAt       time.Time      `json:"firstSeenAt"`
	LastSeenAt        time.Time      `json:"lastSeenAt"`
	ResolvedAt        *time.Time     `json:"resolvedAt"`
	CVE               CVESummary     `json:"cve"`
	References        []string       `json:"references,omitempty"`
	Metadata          map[string]any `json:"metadata,omitempty"`
}

type CVESummary struct {
	Title             string     `json:"title"`
	Description       string     `json:"description"`
	PublishedAt       *time.Time `json:"publishedAt"`
	ModifiedAt        *time.Time `json:"modifiedAt"`
	Rejected          bool       `json:"rejected"`
	KEVDueDate        *time.Time `json:"kevDueDate"`
	KEVVendorProject  string     `json:"kevVendorProject"`
	KEVProduct        string     `json:"kevProduct"`
	KEVRequiredAction string     `json:"kevRequiredAction"`
}

type FindingBatch struct {
	ContractVersion string    `json:"contractVersion"`
	OrgID           string    `json:"orgId"`
	BatchID         string    `json:"batchId"`
	GeneratedAt     time.Time `json:"generatedAt"`
	Findings        []Finding `json:"findings"`
}

type ConnectionHealth struct {
	Configured          bool       `json:"configured"`
	Enabled             bool       `json:"enabled"`
	LastInventoryPushAt *time.Time `json:"lastInventoryPushAt"`
	LastFindingIngestAt *time.Time `json:"lastFindingIngestAt"`
	LastHealthCheckAt   *time.Time `json:"lastHealthCheckAt"`
	LastErrorCode       string     `json:"lastErrorCode"`
	LastErrorAt         *time.Time `json:"lastErrorAt"`
	ContractVersion     string     `json:"contractVersion"`
}
