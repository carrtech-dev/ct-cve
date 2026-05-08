package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/carrtech-dev/ct-cve/internal/ctops"
	"github.com/carrtech-dev/ct-cve/internal/vuln"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type affectedRecord struct {
	Affected vuln.AffectedPackage
	CVE      ctops.CVESummary
	CVSS     *float64
	KEV      bool
}

func (s *PostgresStore) RememberNonce(ctx context.Context, tokenID, nonce string, expiresAt, now time.Time) (bool, error) {
	if _, err := s.pool.Exec(ctx, `DELETE FROM ct_cve_service_nonces WHERE expires_at <= $1`, now); err != nil {
		return false, err
	}
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO ct_cve_service_nonces (token_id, nonce, expires_at)
		VALUES ($1,$2,$3)
		ON CONFLICT DO NOTHING
	`, tokenID, nonce, expiresAt)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *PostgresStore) ApplyInventorySnapshot(ctx context.Context, snapshot ctops.InventorySnapshot, now time.Time) (ctops.InventorySnapshotApplyResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ctops.InventorySnapshotApplyResult{}, err
	}
	defer tx.Rollback(ctx)

	if replayed, ok, err := getSnapshotResponse(ctx, tx, snapshot.OrgID, snapshot.SnapshotID); err != nil {
		return ctops.InventorySnapshotApplyResult{}, err
	} else if ok {
		return ctops.InventorySnapshotApplyResult{Response: replayed, Replayed: true}, tx.Commit(ctx)
	}

	for _, host := range snapshot.Hosts {
		if err := upsertCTOpsHost(ctx, tx, snapshot.OrgID, host); err != nil {
			return ctops.InventorySnapshotApplyResult{}, err
		}
	}
	for _, pkg := range snapshot.Packages {
		if err := upsertCTOpsPackage(ctx, tx, snapshot.OrgID, pkg); err != nil {
			return ctops.InventorySnapshotApplyResult{}, err
		}
	}

	findings, err := matchSnapshotFindings(ctx, tx, snapshot, now)
	if err != nil {
		return ctops.InventorySnapshotApplyResult{}, err
	}

	result := ctops.InventorySnapshotResult{
		Accepted:         true,
		SnapshotID:       snapshot.SnapshotID,
		HostsAccepted:    len(snapshot.Hosts),
		PackagesAccepted: len(snapshot.Packages),
		RowsRejected:     0,
		NextAction:       "none",
	}
	if err := insertSnapshotResponse(ctx, tx, snapshot, result); err != nil {
		return ctops.InventorySnapshotApplyResult{}, err
	}
	if err := touchInventoryStatus(ctx, tx, snapshot.OrgID, now); err != nil {
		return ctops.InventorySnapshotApplyResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ctops.InventorySnapshotApplyResult{}, err
	}
	return ctops.InventorySnapshotApplyResult{Response: result, Findings: findings}, nil
}

func (s *PostgresStore) RecordFindingDelivery(ctx context.Context, orgID, _ string, _ int) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ct_ops_connection_status (org_id, configured, enabled, last_finding_ingest_at, last_error_code, last_error_at, updated_at)
		VALUES ($1, true, true, NOW(), '', NULL, NOW())
		ON CONFLICT (org_id) DO UPDATE SET
			configured = true,
			enabled = true,
			last_finding_ingest_at = EXCLUDED.last_finding_ingest_at,
			last_error_code = '',
			last_error_at = NULL,
			updated_at = NOW()
	`, orgID)
	return err
}

func (s *PostgresStore) RecordConnectionError(ctx context.Context, orgID, code string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ct_ops_connection_status (org_id, configured, enabled, last_error_code, last_error_at, updated_at)
		VALUES ($1, true, true, $2, NOW(), NOW())
		ON CONFLICT (org_id) DO UPDATE SET
			configured = true,
			enabled = true,
			last_error_code = EXCLUDED.last_error_code,
			last_error_at = EXCLUDED.last_error_at,
			updated_at = NOW()
	`, orgID, code)
	return err
}

func (s *PostgresStore) UpdateInventorySnapshotResponse(ctx context.Context, orgID, snapshotID string, result ctops.InventorySnapshotResult) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE ct_ops_inventory_snapshots
		SET response_json = $3, updated_at = NOW()
		WHERE org_id = $1 AND snapshot_id = $2
	`, orgID, snapshotID, raw)
	return err
}

func (s *PostgresStore) ConnectionHealth(ctx context.Context, orgID string) (ctops.ConnectionHealth, error) {
	var health ctops.ConnectionHealth
	var lastInventory, lastFinding, lastHealth, lastError pgtype.Timestamptz
	err := s.pool.QueryRow(ctx, `
		SELECT configured, enabled, last_inventory_push_at, last_finding_ingest_at,
			last_health_check_at, last_error_code, last_error_at
		FROM ct_ops_connection_status
		WHERE org_id = $1
	`, orgID).Scan(
		&health.Configured,
		&health.Enabled,
		&lastInventory,
		&lastFinding,
		&lastHealth,
		&health.LastErrorCode,
		&lastError,
	)
	if err == pgx.ErrNoRows {
		return ctops.ConnectionHealth{Configured: true, Enabled: true, ContractVersion: ctops.ContractVersion}, nil
	}
	if err != nil {
		return ctops.ConnectionHealth{}, err
	}
	if lastInventory.Valid {
		health.LastInventoryPushAt = &lastInventory.Time
	}
	if lastFinding.Valid {
		health.LastFindingIngestAt = &lastFinding.Time
	}
	if lastHealth.Valid {
		health.LastHealthCheckAt = &lastHealth.Time
	}
	if lastError.Valid {
		health.LastErrorAt = &lastError.Time
	}
	health.ContractVersion = ctops.ContractVersion
	return health, nil
}

func (s *PostgresStore) RecordConnectionHealth(ctx context.Context, orgID string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ct_ops_connection_status (org_id, configured, enabled, last_health_check_at, updated_at)
		VALUES ($1, true, true, NOW(), NOW())
		ON CONFLICT (org_id) DO UPDATE SET
			configured = true,
			enabled = true,
			last_health_check_at = EXCLUDED.last_health_check_at,
			updated_at = NOW()
	`, orgID)
	return err
}

func getSnapshotResponse(ctx context.Context, tx pgx.Tx, orgID, snapshotID string) (ctops.InventorySnapshotResult, bool, error) {
	var raw []byte
	err := tx.QueryRow(ctx, `
		SELECT response_json
		FROM ct_ops_inventory_snapshots
		WHERE org_id = $1 AND snapshot_id = $2
	`, orgID, snapshotID).Scan(&raw)
	if err == pgx.ErrNoRows {
		return ctops.InventorySnapshotResult{}, false, nil
	}
	if err != nil {
		return ctops.InventorySnapshotResult{}, false, err
	}
	var result ctops.InventorySnapshotResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return ctops.InventorySnapshotResult{}, false, err
	}
	return result, true, nil
}

func insertSnapshotResponse(ctx context.Context, tx pgx.Tx, snapshot ctops.InventorySnapshot, result ctops.InventorySnapshotResult) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO ct_ops_inventory_snapshots (
			org_id, snapshot_id, contract_version, snapshot_type, generated_at, cursor_value,
			hosts_accepted, packages_accepted, rows_rejected, response_json, created_at, updated_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW(),NOW())
	`, snapshot.OrgID, snapshot.SnapshotID, snapshot.ContractVersion, snapshot.SnapshotType, snapshot.GeneratedAt,
		snapshot.Cursor, result.HostsAccepted, result.PackagesAccepted, result.RowsRejected, raw)
	return err
}

func upsertCTOpsHost(ctx context.Context, tx pgx.Tx, orgID string, host ctops.InventoryHost) error {
	ipAddresses, err := json.Marshal(host.IPAddresses)
	if err != nil {
		return err
	}
	status := strings.TrimSpace(host.Status)
	if status == "" {
		status = "unknown"
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO ct_ops_hosts (
			org_id, host_id, agent_id, hostname, display_name, os, os_version, arch,
			ip_addresses, status, last_seen_at, deleted_at, created_at, updated_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW(),NOW())
		ON CONFLICT (org_id, host_id) DO UPDATE SET
			agent_id = EXCLUDED.agent_id,
			hostname = EXCLUDED.hostname,
			display_name = EXCLUDED.display_name,
			os = EXCLUDED.os,
			os_version = EXCLUDED.os_version,
			arch = EXCLUDED.arch,
			ip_addresses = EXCLUDED.ip_addresses,
			status = EXCLUDED.status,
			last_seen_at = EXCLUDED.last_seen_at,
			deleted_at = EXCLUDED.deleted_at,
			updated_at = NOW()
	`, orgID, host.HostID, host.AgentID, host.Hostname, host.DisplayName, host.OS, host.OSVersion, host.Arch,
		ipAddresses, status, host.LastSeenAt, host.DeletedAt)
	return err
}

func upsertCTOpsPackage(ctx context.Context, tx pgx.Tx, orgID string, pkg ctops.InventoryPackage) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO ct_ops_software_packages (
			org_id, package_id, host_id, name, version, architecture, source, fingerprint,
			distro_id, distro_version_id, distro_codename, distro_id_like, source_name, source_version,
			package_epoch, package_release, repository, origin, install_date, first_seen_at, last_seen_at,
			removed_at, deleted_at, created_at, updated_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,NOW(),NOW())
		ON CONFLICT (org_id, package_id) DO UPDATE SET
			host_id = EXCLUDED.host_id,
			name = EXCLUDED.name,
			version = EXCLUDED.version,
			architecture = EXCLUDED.architecture,
			source = EXCLUDED.source,
			fingerprint = EXCLUDED.fingerprint,
			distro_id = EXCLUDED.distro_id,
			distro_version_id = EXCLUDED.distro_version_id,
			distro_codename = EXCLUDED.distro_codename,
			distro_id_like = EXCLUDED.distro_id_like,
			source_name = EXCLUDED.source_name,
			source_version = EXCLUDED.source_version,
			package_epoch = EXCLUDED.package_epoch,
			package_release = EXCLUDED.package_release,
			repository = EXCLUDED.repository,
			origin = EXCLUDED.origin,
			install_date = EXCLUDED.install_date,
			first_seen_at = LEAST(ct_ops_software_packages.first_seen_at, EXCLUDED.first_seen_at),
			last_seen_at = EXCLUDED.last_seen_at,
			removed_at = EXCLUDED.removed_at,
			deleted_at = EXCLUDED.deleted_at,
			updated_at = NOW()
	`, orgID, pkg.SoftwarePackageID, pkg.HostID, pkg.Name, pkg.Version, pkg.Architecture, pkg.Source, pkg.Fingerprint,
		pkg.DistroID, pkg.DistroVersionID, pkg.DistroCodename, pkg.DistroIDLike, pkg.SourceName, pkg.SourceVersion,
		pkg.PackageEpoch, pkg.PackageRelease, pkg.Repository, pkg.Origin, pkg.InstallDate, pkg.FirstSeenAt,
		pkg.LastSeenAt, pkg.RemovedAt, pkg.DeletedAt)
	return err
}

func matchSnapshotFindings(ctx context.Context, tx pgx.Tx, snapshot ctops.InventorySnapshot, now time.Time) ([]ctops.Finding, error) {
	candidates, err := affectedCandidates(ctx, tx, snapshot.Packages)
	if err != nil {
		return nil, err
	}
	hostDeleted := make(map[string]bool, len(snapshot.Hosts))
	for _, host := range snapshot.Hosts {
		hostDeleted[host.HostID] = host.DeletedAt != nil
	}

	touchedPackageIDs := make([]string, 0, len(snapshot.Packages))
	matchedKeys := map[string]bool{}
	findings := make([]ctops.Finding, 0)
	for _, pkg := range snapshot.Packages {
		touchedPackageIDs = append(touchedPackageIDs, pkg.SoftwarePackageID)
		if pkg.RemovedAt != nil || pkg.DeletedAt != nil || hostDeleted[pkg.HostID] {
			continue
		}
		inventory := vuln.InventoryPackage{
			ID:              pkg.SoftwarePackageID,
			OrganisationID:  snapshot.OrgID,
			HostID:          pkg.HostID,
			Name:            pkg.Name,
			Version:         pkg.Version,
			Source:          pkg.Source,
			DistroID:        stringPtrValue(pkg.DistroID),
			DistroIDLike:    pkg.DistroIDLike,
			DistroVersionID: stringPtrValue(pkg.DistroVersionID),
			DistroCodename:  stringPtrValue(pkg.DistroCodename),
			SourceName:      stringPtrValue(pkg.SourceName),
			SourceVersion:   stringPtrValue(pkg.SourceVersion),
			Repository:      stringPtrValue(pkg.Repository),
		}
		for _, candidate := range candidates {
			matched, reason := vuln.MatchPackage(inventory, candidate.Affected)
			if !matched {
				continue
			}
			finding := findingFromMatch(snapshot.OrgID, pkg, candidate, reason, now, nil)
			matchedKeys[findingKey(finding.HostID, finding.SoftwarePackageID, finding.CVEID)] = true
			if err := upsertOpenFinding(ctx, tx, snapshot.OrgID, finding, now); err != nil {
				return nil, err
			}
			findings = append(findings, finding)
		}
	}

	resolved, err := resolveStaleFindings(ctx, tx, snapshot.OrgID, touchedPackageIDs, matchedKeys, now)
	if err != nil {
		return nil, err
	}
	findings = append(findings, resolved...)
	return findings, nil
}

func affectedCandidates(ctx context.Context, tx pgx.Tx, packages []ctops.InventoryPackage) ([]affectedRecord, error) {
	names := make([]string, 0, len(packages)*2)
	seen := map[string]bool{}
	for _, pkg := range packages {
		for _, name := range []string{pkg.Name, stringPtrValue(pkg.SourceName)} {
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT ap.cve_id, ap.source, ap.distro_id, ap.distro_version_id, ap.distro_codename,
			ap.package_name, ap.source_package_name, ap.fixed_version, ap.affected_versions,
			ap.repository, ap.severity, ap.package_state, ap.metadata_json,
			cr.title, cr.description, cr.cvss_score::float8, cr.published_at, cr.modified_at,
			cr.rejected, cr.known_exploited, cr.kev_due_date::timestamptz, cr.kev_vendor_project, cr.kev_product,
			cr.kev_required_action
		FROM affected_packages ap
		JOIN cve_records cr ON cr.cve_id = ap.cve_id
		WHERE ap.package_name = ANY($1) OR ap.source_package_name = ANY($1)
	`, names)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var candidates []affectedRecord
	for rows.Next() {
		var row affectedRecord
		var severity string
		var cvss pgtype.Float8
		var published, modified, kevDue pgtype.Timestamptz
		if err := rows.Scan(
			&row.Affected.CVEID,
			&row.Affected.Source,
			&row.Affected.DistroID,
			&row.Affected.DistroVersionID,
			&row.Affected.DistroCodename,
			&row.Affected.PackageName,
			&row.Affected.SourcePackageName,
			&row.Affected.FixedVersion,
			&row.Affected.AffectedVersions,
			&row.Affected.Repository,
			&severity,
			&row.Affected.PackageState,
			&row.Affected.MetadataJSON,
			&row.CVE.Title,
			&row.CVE.Description,
			&cvss,
			&published,
			&modified,
			&row.CVE.Rejected,
			&row.KEV,
			&kevDue,
			&row.CVE.KEVVendorProject,
			&row.CVE.KEVProduct,
			&row.CVE.KEVRequiredAction,
		); err != nil {
			return nil, err
		}
		row.Affected.Severity = vuln.Severity(severity)
		if cvss.Valid {
			value := cvss.Float64
			row.CVSS = &value
		}
		if published.Valid {
			row.CVE.PublishedAt = &published.Time
		}
		if modified.Valid {
			row.CVE.ModifiedAt = &modified.Time
		}
		if kevDue.Valid {
			row.CVE.KEVDueDate = &kevDue.Time
		}
		candidates = append(candidates, row)
	}
	return candidates, rows.Err()
}

func findingFromMatch(orgID string, pkg ctops.InventoryPackage, candidate affectedRecord, reason string, now time.Time, resolvedAt *time.Time) ctops.Finding {
	status := ctops.FindingStatusOpen
	if resolvedAt != nil {
		status = ctops.FindingStatusResolved
	}
	severity := string(candidate.Affected.Severity)
	if severity == "" {
		severity = "unknown"
	}
	return ctops.Finding{
		FindingID:         stableFindingID(orgID, pkg.HostID, pkg.SoftwarePackageID, candidate.Affected.CVEID),
		HostID:            pkg.HostID,
		SoftwarePackageID: pkg.SoftwarePackageID,
		CVEID:             candidate.Affected.CVEID,
		Status:            status,
		PackageName:       pkg.Name,
		InstalledVersion:  pkg.Version,
		FixedVersion:      candidate.Affected.FixedVersion,
		Source:            candidate.Affected.Source,
		Severity:          severity,
		CVSSScore:         candidate.CVSS,
		KnownExploited:    candidate.KEV,
		Confidence:        "confirmed",
		MatchReason:       reason,
		FirstSeenAt:       now,
		LastSeenAt:        now,
		ResolvedAt:        resolvedAt,
		CVE:               candidate.CVE,
	}
}

func upsertOpenFinding(ctx context.Context, tx pgx.Tx, orgID string, finding ctops.Finding, now time.Time) error {
	metadata, err := json.Marshal(map[string]any{"ctCveFindingId": finding.FindingID})
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO integration_findings (
			id, finding_id, org_id, host_id, package_id, cve_id, confidence, reason,
			first_seen_at, last_seen_at, resolved_at, package_name, installed_version,
			fixed_version, source, severity, cvss_score, known_exploited, metadata_json,
			created_at, updated_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL,$11,$12,$13,$14,$15,$16,$17,$18,NOW(),NOW())
		ON CONFLICT (org_id, host_id, package_id, cve_id) DO UPDATE SET
			finding_id = EXCLUDED.finding_id,
			confidence = EXCLUDED.confidence,
			reason = EXCLUDED.reason,
			first_seen_at = LEAST(integration_findings.first_seen_at, EXCLUDED.first_seen_at),
			last_seen_at = EXCLUDED.last_seen_at,
			resolved_at = NULL,
			package_name = EXCLUDED.package_name,
			installed_version = EXCLUDED.installed_version,
			fixed_version = EXCLUDED.fixed_version,
			source = EXCLUDED.source,
			severity = EXCLUDED.severity,
			cvss_score = EXCLUDED.cvss_score,
			known_exploited = EXCLUDED.known_exploited,
			metadata_json = EXCLUDED.metadata_json,
			updated_at = NOW()
	`, randomUUID(), finding.FindingID, orgID, finding.HostID, finding.SoftwarePackageID, finding.CVEID,
		finding.Confidence, finding.MatchReason, finding.FirstSeenAt, finding.LastSeenAt, finding.PackageName,
		finding.InstalledVersion, finding.FixedVersion, finding.Source, finding.Severity, finding.CVSSScore,
		finding.KnownExploited, metadata)
	_ = now
	return err
}

func resolveStaleFindings(ctx context.Context, tx pgx.Tx, orgID string, packageIDs []string, matchedKeys map[string]bool, now time.Time) ([]ctops.Finding, error) {
	if len(packageIDs) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT f.finding_id, f.host_id, f.package_id, f.cve_id, f.package_name, f.installed_version,
			COALESCE(f.fixed_version, ''), f.source, f.severity, f.cvss_score::float8, f.known_exploited,
			f.confidence, f.reason, f.first_seen_at, f.last_seen_at,
			cr.title, cr.description, cr.published_at, cr.modified_at, cr.rejected, cr.known_exploited,
			cr.kev_due_date::timestamptz, cr.kev_vendor_project, cr.kev_product, cr.kev_required_action
		FROM integration_findings f
		JOIN cve_records cr ON cr.cve_id = f.cve_id
		WHERE f.org_id = $1 AND f.package_id = ANY($2) AND f.resolved_at IS NULL
	`, orgID, packageIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var resolved []ctops.Finding
	for rows.Next() {
		var finding ctops.Finding
		var cvss pgtype.Float8
		var published, modified, kevDue pgtype.Timestamptz
		var cveKnownExploited bool
		if err := rows.Scan(
			&finding.FindingID,
			&finding.HostID,
			&finding.SoftwarePackageID,
			&finding.CVEID,
			&finding.PackageName,
			&finding.InstalledVersion,
			&finding.FixedVersion,
			&finding.Source,
			&finding.Severity,
			&cvss,
			&finding.KnownExploited,
			&finding.Confidence,
			&finding.MatchReason,
			&finding.FirstSeenAt,
			&finding.LastSeenAt,
			&finding.CVE.Title,
			&finding.CVE.Description,
			&published,
			&modified,
			&finding.CVE.Rejected,
			&cveKnownExploited,
			&kevDue,
			&finding.CVE.KEVVendorProject,
			&finding.CVE.KEVProduct,
			&finding.CVE.KEVRequiredAction,
		); err != nil {
			return nil, err
		}
		if matchedKeys[findingKey(finding.HostID, finding.SoftwarePackageID, finding.CVEID)] {
			continue
		}
		if cvss.Valid {
			value := cvss.Float64
			finding.CVSSScore = &value
		}
		if published.Valid {
			finding.CVE.PublishedAt = &published.Time
		}
		if modified.Valid {
			finding.CVE.ModifiedAt = &modified.Time
		}
		if kevDue.Valid {
			finding.CVE.KEVDueDate = &kevDue.Time
		}
		resolvedAt := now
		finding.Status = ctops.FindingStatusResolved
		finding.ResolvedAt = &resolvedAt
		finding.LastSeenAt = now
		resolved = append(resolved, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, finding := range resolved {
		if _, err := tx.Exec(ctx, `
			UPDATE integration_findings
			SET resolved_at = $5, last_seen_at = $5, updated_at = NOW()
			WHERE org_id = $1 AND host_id = $2 AND package_id = $3 AND cve_id = $4
		`, orgID, finding.HostID, finding.SoftwarePackageID, finding.CVEID, now); err != nil {
			return nil, err
		}
	}
	return resolved, nil
}

func touchInventoryStatus(ctx context.Context, tx pgx.Tx, orgID string, now time.Time) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO ct_ops_connection_status (org_id, configured, enabled, last_inventory_push_at, updated_at)
		VALUES ($1, true, true, $2, NOW())
		ON CONFLICT (org_id) DO UPDATE SET
			configured = true,
			enabled = true,
			last_inventory_push_at = EXCLUDED.last_inventory_push_at,
			updated_at = NOW()
	`, orgID, now)
	return err
}

func stableFindingID(orgID, hostID, packageID, cveID string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{orgID, hostID, packageID, cveID}, "\x00")))
	return "ctcve_find_" + hex.EncodeToString(sum[:])[:24]
}

func findingKey(hostID, packageID, cveID string) string {
	return hostID + "\x00" + packageID + "\x00" + cveID
}

func randomUUID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
		copy(raw[:], sum[:16])
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
}

func stringPtrValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
