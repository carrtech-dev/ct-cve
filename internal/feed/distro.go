package feed

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var rpmELVersionPattern = regexp.MustCompile(`(?:^|[._-])el([0-9]+)(?:[._-]|$)`)

func ParseDebianTracker(r io.Reader) (FetchResult, error) {
	var doc map[string]map[string]struct {
		Description string `json:"description"`
		Releases    map[string]struct {
			Status       string `json:"status"`
			FixedVersion string `json:"fixed_version"`
			Urgency      string `json:"urgency"`
		} `json:"releases"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return FetchResult{}, err
	}

	cves := make(map[string]CVERecord)
	var affected []AffectedPackage
	for pkgName, byCVE := range doc {
		for cveID, entry := range byCVE {
			if _, ok := cves[cveID]; !ok {
				cves[cveID] = CVERecord{
					CVEID:       cveID,
					Description: strings.TrimSpace(entry.Description),
					Severity:    SeverityUnknown,
					Source:      SourceDebianTracker,
				}
			}
			for codename, rel := range entry.Releases {
				if !debianReleaseCanAffect(rel.Status, rel.FixedVersion) {
					continue
				}
				affected = append(affected, AffectedPackage{
					CVEID:          cveID,
					Source:         SourceDebianTracker,
					DistroID:       "debian",
					DistroCodename: codename,
					PackageName:    pkgName,
					FixedVersion:   cleanFixedVersion(rel.FixedVersion),
					Severity:       normalizeSeverity(rel.Urgency),
					PackageState:   strings.TrimSpace(rel.Status),
				})
			}
		}
	}

	records := make([]CVERecord, 0, len(cves))
	for _, record := range cves {
		records = append(records, record)
	}
	return FetchResult{Records: records, AffectedPackages: affected}, nil
}

func debianReleaseCanAffect(status, fixed string) bool {
	status = strings.ToLower(strings.TrimSpace(status))
	fixed = strings.TrimSpace(fixed)
	if status == "not-affected" || status == "undetermined" {
		return false
	}
	return fixed != "" && !strings.HasPrefix(fixed, "<")
}

func ParseAlpineSecDB(r io.Reader, release, repository string) (FetchResult, error) {
	var doc struct {
		Packages []struct {
			Pkg struct {
				Name string `json:"name"`
			} `json:"pkg"`
			Secfixes map[string][]string `json:"secfixes"`
		} `json:"packages"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return FetchResult{}, err
	}

	release = strings.TrimPrefix(strings.TrimSpace(release), "v")
	cves := make(map[string]CVERecord)
	var affected []AffectedPackage
	for _, pkg := range doc.Packages {
		name := strings.TrimSpace(pkg.Pkg.Name)
		if name == "" {
			continue
		}
		for fixedVersion, cveIDs := range pkg.Secfixes {
			fixedVersion = cleanFixedVersion(fixedVersion)
			if fixedVersion == "" {
				continue
			}
			for _, cveID := range cveIDs {
				cveID = strings.TrimSpace(cveID)
				if cveID == "" || !strings.HasPrefix(cveID, "CVE-") {
					continue
				}
				cves[cveID] = CVERecord{CVEID: cveID, Severity: SeverityUnknown, Source: SourceAlpineSecDB}
				affected = append(affected, AffectedPackage{
					CVEID:           cveID,
					Source:          SourceAlpineSecDB,
					DistroID:        "alpine",
					DistroVersionID: release,
					PackageName:     name,
					FixedVersion:    fixedVersion,
					Repository:      strings.TrimSpace(repository),
					Severity:        SeverityUnknown,
				})
			}
		}
	}

	records := make([]CVERecord, 0, len(cves))
	for _, record := range cves {
		records = append(records, record)
	}
	return FetchResult{Records: records, AffectedPackages: affected}, nil
}

func ParseUbuntuOSVDocument(r io.Reader) (FetchResult, error) {
	var doc struct {
		ID       string   `json:"id"`
		Details  string   `json:"details"`
		Aliases  []string `json:"aliases"`
		Upstream []string `json:"upstream"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
		Published string `json:"published"`
		Modified  string `json:"modified"`
		Affected  []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
				Purl      string `json:"purl"`
			} `json:"package"`
			Ranges []struct {
				Events []struct {
					Fixed string `json:"fixed"`
				} `json:"events"`
			} `json:"ranges"`
			Versions []string `json:"versions"`
		} `json:"affected"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return FetchResult{}, err
	}

	cveID := firstCVE(doc.Upstream)
	if cveID == "" {
		cveID = firstCVE(doc.Aliases)
	}
	if cveID == "" && strings.Contains(doc.ID, "CVE-") {
		cveID = strings.TrimPrefix(doc.ID, "UBUNTU-")
	}
	if cveID == "" {
		return FetchResult{}, nil
	}

	record := CVERecord{
		CVEID:       cveID,
		Description: strings.TrimSpace(doc.Details),
		Severity:    ubuntuSeverity(doc.Severity),
		Source:      SourceUbuntuOSV,
	}
	if t := parseRFC3339(doc.Published); t != nil {
		record.PublishedAt = t
	}
	if t := parseRFC3339(doc.Modified); t != nil {
		record.ModifiedAt = t
	}

	var affected []AffectedPackage
	for _, a := range doc.Affected {
		if strings.TrimSpace(a.Package.Name) == "" {
			continue
		}
		versionID, codename := parseUbuntuEcosystem(a.Package.Ecosystem, a.Package.Purl)
		fixed := ""
		for _, rng := range a.Ranges {
			for _, event := range rng.Events {
				if event.Fixed != "" {
					fixed = event.Fixed
				}
			}
		}
		affected = append(affected, AffectedPackage{
			CVEID:            cveID,
			Source:           SourceUbuntuOSV,
			DistroID:         "ubuntu",
			DistroVersionID:  versionID,
			DistroCodename:   codename,
			PackageName:      strings.TrimSpace(a.Package.Name),
			FixedVersion:     cleanFixedVersion(fixed),
			AffectedVersions: a.Versions,
			Severity:         record.Severity,
		})
	}
	return FetchResult{Records: []CVERecord{record}, AffectedPackages: affected}, nil
}

func ParseRedHatCSAFList(r io.Reader) (FetchResult, error) {
	var rows []struct {
		RHSA             string   `json:"RHSA"`
		Severity         string   `json:"severity"`
		ReleasedOn       string   `json:"released_on"`
		CVEs             []string `json:"CVEs"`
		ReleasedPackages []string `json:"released_packages"`
		ResourceURL      string   `json:"resource_url"`
	}
	if err := json.NewDecoder(r).Decode(&rows); err != nil {
		return FetchResult{}, err
	}

	recordsByCVE := make(map[string]CVERecord)
	var affected []AffectedPackage
	for _, row := range rows {
		severity := normalizeSeverity(row.Severity)
		var releasedAt *time.Time
		if t := parseRFC3339(row.ReleasedOn); t != nil {
			releasedAt = t
		}
		cveIDs := uniqueNonEmptyStrings(row.CVEs)
		if len(cveIDs) == 0 {
			continue
		}
		for _, cveID := range cveIDs {
			if _, ok := recordsByCVE[cveID]; !ok {
				recordsByCVE[cveID] = CVERecord{
					CVEID:       cveID,
					Severity:    severity,
					PublishedAt: releasedAt,
					ModifiedAt:  releasedAt,
					Source:      SourceRedHatSecurityData,
				}
			}
		}
		for _, pkg := range row.ReleasedPackages {
			name, fixed := splitRedHatFixedPackage(pkg)
			if name == "" || fixed == "" {
				continue
			}
			distroVersion := redHatVersionFromFixedEVR(fixed)
			if distroVersion == "" {
				continue
			}
			for _, cveID := range cveIDs {
				affected = append(affected, AffectedPackage{
					CVEID:           cveID,
					Source:          SourceRedHatSecurityData,
					DistroID:        "rhel",
					DistroVersionID: distroVersion,
					PackageName:     name,
					FixedVersion:    fixed,
					Severity:        severity,
					PackageState:    "fixed",
					MetadataJSON: encodeMetadata(map[string]string{
						"advisory":     row.RHSA,
						"released_on":  row.ReleasedOn,
						"package":      pkg,
						"resource_url": row.ResourceURL,
						"source":       "csaf",
					}),
				})
			}
		}
	}

	records := make([]CVERecord, 0, len(recordsByCVE))
	for _, record := range recordsByCVE {
		records = append(records, record)
	}
	return FetchResult{Records: records, AffectedPackages: affected}, nil
}

func firstCVE(values []string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if strings.HasPrefix(value, "CVE-") {
			return value
		}
	}
	return ""
}

func ubuntuSeverity(items []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) Severity {
	for _, item := range items {
		if strings.EqualFold(item.Type, "Ubuntu") {
			return normalizeSeverity(item.Score)
		}
	}
	return SeverityUnknown
}

func parseUbuntuEcosystem(ecosystem, purl string) (versionID, codename string) {
	for _, part := range strings.Split(ecosystem, ":") {
		if strings.Count(part, ".") == 1 && len(part) >= 4 {
			versionID = part
			break
		}
	}
	if parsed, err := url.Parse(purl); err == nil {
		distro := parsed.Query().Get("distro")
		if _, after, ok := strings.Cut(distro, "/"); ok {
			codename = after
		} else if distro != "" {
			codename = distro
		}
	}
	return versionID, codename
}

func parseRFC3339(value string) *time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil
	}
	return &t
}

func cleanFixedVersion(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "0" || strings.HasPrefix(value, "<") {
		return ""
	}
	return value
}

func encodeMetadata(v any) []byte {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

func uniqueNonEmptyStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func splitRedHatFixedPackage(value string) (name, fixed string) {
	value = strings.TrimSpace(value)
	value = strings.TrimSuffix(value, ".src.rpm")
	value = strings.TrimSuffix(value, ".rpm")
	value = stripRPMArchitecture(value)
	if value == "" {
		return "", ""
	}

	releaseDash := strings.LastIndex(value, "-")
	if releaseDash <= 0 || releaseDash == len(value)-1 {
		return "", ""
	}
	release := value[releaseDash+1:]
	beforeRelease := value[:releaseDash]

	versionDash := strings.LastIndex(beforeRelease, "-")
	if versionDash <= 0 || versionDash == len(beforeRelease)-1 {
		return "", ""
	}
	name = strings.TrimSpace(beforeRelease[:versionDash])
	version := strings.TrimSpace(beforeRelease[versionDash+1:])
	if name == "" || version == "" || release == "" {
		return "", ""
	}
	return name, version + "-" + release
}

func stripRPMArchitecture(value string) string {
	idx := strings.LastIndex(value, ".")
	if idx <= 0 || idx == len(value)-1 {
		return value
	}
	switch value[idx+1:] {
	case "aarch64", "i386", "i486", "i586", "i686", "noarch", "ppc64le", "s390x", "src", "x86_64":
		return value[:idx]
	default:
		return value
	}
}

func redHatVersionFromFixedEVR(fixed string) string {
	match := rpmELVersionPattern.FindStringSubmatch(fixed)
	if len(match) != 2 {
		return ""
	}
	return match[1]
}

func parseFloat(value string) (float64, error) {
	var out float64
	_, err := fmt.Sscanf(value, "%f", &out)
	return out, err
}
