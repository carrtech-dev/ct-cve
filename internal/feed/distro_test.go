package feed

import (
	"strings"
	"testing"
)

func TestParseDebianTracker(t *testing.T) {
	t.Parallel()

	doc := `{
	  "openssl": {
	    "CVE-2024-1234": {
	      "description": "test vuln",
	      "releases": {
	        "bookworm": {"status": "open", "fixed_version": "3.0.11-1~deb12u2", "urgency": "high"},
	        "bullseye": {"status": "resolved", "fixed_version": "1.1.1w-0+deb11u1", "urgency": "medium"},
	        "sid": {"status": "not-affected", "fixed_version": "", "urgency": "unimportant"}
	      }
	    }
	  }
	}`
	result, err := ParseDebianTracker(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("ParseDebianTracker: %v", err)
	}
	if len(result.Records) != 1 || result.Records[0].CVEID != "CVE-2024-1234" {
		t.Fatalf("unexpected CVEs: %#v", result.Records)
	}
	if len(result.AffectedPackages) != 2 {
		t.Fatalf("len(affected) = %d, want 2", len(result.AffectedPackages))
	}
	row := result.AffectedPackages[0]
	if row.Source != SourceDebianTracker || row.DistroID != "debian" || row.PackageName != "openssl" {
		t.Fatalf("unexpected affected row identity: %#v", row)
	}
}

func TestParseAlpineSecDB(t *testing.T) {
	t.Parallel()

	doc := `{"packages":[{"pkg":{"name":"openssl"},"secfixes":{"3.1.4-r1":["CVE-2024-1234","CVE-2024-9999","GHSA-ignore"]}}]}`
	result, err := ParseAlpineSecDB(strings.NewReader(doc), "v3.19", "main")
	if err != nil {
		t.Fatalf("ParseAlpineSecDB: %v", err)
	}
	if len(result.Records) != 2 || len(result.AffectedPackages) != 2 {
		t.Fatalf("records=%d affected=%d, want 2 and 2", len(result.Records), len(result.AffectedPackages))
	}
	row := result.AffectedPackages[0]
	if row.Source != SourceAlpineSecDB || row.DistroVersionID != "3.19" || row.Repository != "main" || row.FixedVersion != "3.1.4-r1" {
		t.Fatalf("unexpected affected row: %#v", row)
	}
}

func TestParseUbuntuOSVDocument(t *testing.T) {
	t.Parallel()

	doc := `{
	  "id": "UBUNTU-CVE-2024-1234",
	  "details": "openssl issue",
	  "aliases": ["CVE-2024-1234"],
	  "severity": [{"type": "Ubuntu", "score": "medium"}],
	  "published": "2024-01-02T03:04:05Z",
	  "modified": "2024-01-03T03:04:05Z",
	  "affected": [{
	    "package": {
	      "ecosystem": "Ubuntu:22.04:LTS",
	      "name": "openssl",
	      "purl": "pkg:deb/ubuntu/openssl?distro=ubuntu/jammy"
	    },
	    "ranges": [{"events": [{"fixed": "3.0.2-0ubuntu1.16"}]}],
	    "versions": ["3.0.2-0ubuntu1"]
	  }]
	}`
	result, err := ParseUbuntuOSVDocument(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("ParseUbuntuOSVDocument: %v", err)
	}
	if len(result.Records) != 1 || result.Records[0].Severity != SeverityMedium {
		t.Fatalf("unexpected records: %#v", result.Records)
	}
	row := result.AffectedPackages[0]
	if row.Source != SourceUbuntuOSV || row.DistroID != "ubuntu" || row.DistroVersionID != "22.04" || row.DistroCodename != "jammy" {
		t.Fatalf("unexpected Ubuntu affected row: %#v", row)
	}
}

func TestParseRedHatCSAFListReleasedPackages(t *testing.T) {
	t.Parallel()

	doc := `[{
	  "RHSA": "RHSA-2026:1473",
	  "severity": "important",
	  "released_on": "2026-01-28T10:08:56Z",
	  "CVEs": ["CVE-2025-66199", "CVE-2025-15467"],
	  "released_packages": [
	    "openssl-1:3.5.1-7.el9_7.x86_64",
	    "openssl-libs-1:3.5.1-7.el9_7.x86_64",
	    "openssl-main@x86_64"
	  ],
	  "resource_url": "https://access.redhat.com/hydra/rest/securitydata/csaf/RHSA-2026:1473.json"
	}]`

	result, err := ParseRedHatCSAFList(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("ParseRedHatCSAFList: %v", err)
	}
	if len(result.Records) != 2 || len(result.AffectedPackages) != 4 {
		t.Fatalf("records=%d affected=%d, want 2 and 4", len(result.Records), len(result.AffectedPackages))
	}
	row := result.AffectedPackages[0]
	if row.Source != SourceRedHatSecurityData || row.DistroID != "rhel" || row.DistroVersionID != "9" || row.PackageState != "fixed" {
		t.Fatalf("unexpected Red Hat affected row: %#v", row)
	}
	if !strings.Contains(string(row.MetadataJSON), "RHSA-2026:1473") {
		t.Fatalf("metadata did not include advisory: %s", string(row.MetadataJSON))
	}
}
