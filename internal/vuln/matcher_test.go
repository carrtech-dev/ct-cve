package vuln

import "testing"

func TestPackageMatchesAffectedRange(t *testing.T) {
	t.Parallel()

	pkg := InventoryPackage{
		ID:              "pkg1",
		HostID:          "host1",
		OrganisationID:  "org1",
		Name:            "libssl3",
		Version:         "3.0.2-0ubuntu1.15",
		Source:          "dpkg",
		DistroID:        "ubuntu",
		DistroVersionID: "22.04",
		DistroCodename:  "jammy",
		SourceName:      "openssl",
	}
	affected := AffectedPackage{
		CVEID:           "CVE-2024-1234",
		Source:          "ubuntu-osv",
		PackageName:     "openssl",
		DistroID:        "ubuntu",
		DistroVersionID: "22.04",
		DistroCodename:  "jammy",
		FixedVersion:    "3.0.2-0ubuntu1.16",
	}

	match, reason := MatchPackage(pkg, affected)
	if !match {
		t.Fatalf("MatchPackage returned false: %s", reason)
	}
}

func TestPackageDoesNotMatchDifferentDistro(t *testing.T) {
	t.Parallel()

	pkg := InventoryPackage{Source: "dpkg", DistroID: "debian", DistroCodename: "bookworm", SourceName: "openssl", Version: "3.0.11-1"}
	affected := AffectedPackage{PackageName: "openssl", DistroID: "ubuntu", DistroCodename: "jammy", FixedVersion: "3.0.2-0ubuntu1.16"}

	match, _ := MatchPackage(pkg, affected)
	if match {
		t.Fatal("expected distro mismatch not to match")
	}
}

func TestPackageWithUnsupportedSourceIsUnassessed(t *testing.T) {
	t.Parallel()

	pkg := InventoryPackage{Source: "homebrew", DistroID: "darwin", Name: "openssl", Version: "3.2.0"}
	affected := AffectedPackage{PackageName: "openssl", DistroID: "ubuntu", FixedVersion: "3.0.2-0ubuntu1.16"}

	match, reason := MatchPackage(pkg, affected)
	if match || reason != "unsupported inventory source" {
		t.Fatalf("MatchPackage = %v, %q; want false unsupported inventory source", match, reason)
	}
}

func TestRPMSourcePackageMatchUsesInstalledEVRWhenSourceVersionIsUpstreamOnly(t *testing.T) {
	t.Parallel()

	pkg := InventoryPackage{
		Name:            "libarchive",
		Version:         "3.5.3-9.el9_7",
		Source:          "rpm",
		DistroID:        "almalinux",
		DistroIDLike:    []string{"rhel", "centos", "fedora"},
		DistroVersionID: "9.7",
		SourceName:      "libarchive",
		SourceVersion:   "3.5.3",
	}
	affected := AffectedPackage{
		Source:          "redhat-security-data",
		DistroID:        "rhel",
		DistroVersionID: "9",
		PackageName:     "libarchive",
		FixedVersion:    "0:3.5.3-9.el9_7",
	}

	match, reason := MatchPackage(pkg, affected)
	if match {
		t.Fatalf("expected installed RPM package not to match, reason=%q", reason)
	}
	if reason != "installed version is fixed" {
		t.Fatalf("reason = %q, want fixed package reason", reason)
	}
}

func TestRPMRHELCompatibleDistroMatchesRedHatAdvisory(t *testing.T) {
	t.Parallel()

	pkg := InventoryPackage{
		Name:            "openssl-libs",
		Version:         "1:3.5.1-5.el9_7",
		Source:          "rpm",
		DistroID:        "almalinux",
		DistroIDLike:    []string{"rhel", "centos", "fedora"},
		DistroVersionID: "9.7",
		SourceName:      "openssl",
		SourceVersion:   "1:3.5.1-5.el9_7",
	}
	affected := AffectedPackage{
		Source:          "redhat-security-data",
		DistroID:        "rhel",
		DistroVersionID: "9",
		PackageName:     "openssl",
		FixedVersion:    "1:3.5.1-7.el9_7",
	}

	match, reason := MatchPackage(pkg, affected)
	if !match {
		t.Fatalf("MatchPackage returned false: %s", reason)
	}
	if reason != "installed rpm evr is below vendor fixed evr" {
		t.Fatalf("reason = %q, want RPM EVR-specific reason", reason)
	}
}
