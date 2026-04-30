package store

import (
	"context"
	"encoding/json"
	"io/fs"
	"path/filepath"
	"sort"

	"github.com/carrtech-dev/ct-cve/internal/feed"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func Open(ctx context.Context, databaseURL string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &PostgresStore{pool: pool}, nil
}

func (s *PostgresStore) Close() {
	s.pool.Close()
}

func (s *PostgresStore) Migrate(ctx context.Context, migrationFS fs.FS) error {
	if _, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)
	`); err != nil {
		return err
	}

	entries, err := fs.ReadDir(migrationFS, ".")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		if err := s.applyMigration(ctx, migrationFS, name); err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgresStore) applyMigration(ctx context.Context, migrationFS fs.FS, name string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var alreadyApplied bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, name).Scan(&alreadyApplied); err != nil {
		return err
	}
	if alreadyApplied {
		return tx.Commit(ctx)
	}

	sql, err := fs.ReadFile(migrationFS, name)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, string(sql)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) UpsertCVERecords(ctx context.Context, records []feed.CVERecord) error {
	for _, record := range records {
		if err := s.upsertCVERecord(ctx, record); err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgresStore) upsertCVERecord(ctx context.Context, record feed.CVERecord) error {
	const q = `
		INSERT INTO cve_records (
			cve_id, title, description, severity, cvss_score, published_at, modified_at,
			rejected, known_exploited, kev_due_date, kev_vendor_project, kev_product,
			kev_required_action, source, metadata_json, created_at, updated_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NOW(),NOW())
		ON CONFLICT (cve_id) DO UPDATE SET
			title = CASE WHEN EXCLUDED.title <> '' THEN EXCLUDED.title ELSE cve_records.title END,
			description = CASE WHEN EXCLUDED.description <> '' THEN EXCLUDED.description ELSE cve_records.description END,
			severity = CASE
				WHEN EXCLUDED.severity <> 'unknown' THEN EXCLUDED.severity
				ELSE cve_records.severity
			END,
			cvss_score = COALESCE(EXCLUDED.cvss_score, cve_records.cvss_score),
			published_at = COALESCE(EXCLUDED.published_at, cve_records.published_at),
			modified_at = COALESCE(EXCLUDED.modified_at, cve_records.modified_at),
			rejected = EXCLUDED.rejected OR cve_records.rejected,
			known_exploited = EXCLUDED.known_exploited OR cve_records.known_exploited,
			kev_due_date = COALESCE(EXCLUDED.kev_due_date, cve_records.kev_due_date),
			kev_vendor_project = CASE WHEN EXCLUDED.kev_vendor_project <> '' THEN EXCLUDED.kev_vendor_project ELSE cve_records.kev_vendor_project END,
			kev_product = CASE WHEN EXCLUDED.kev_product <> '' THEN EXCLUDED.kev_product ELSE cve_records.kev_product END,
			kev_required_action = CASE WHEN EXCLUDED.kev_required_action <> '' THEN EXCLUDED.kev_required_action ELSE cve_records.kev_required_action END,
			source = CASE WHEN EXCLUDED.source <> '' THEN EXCLUDED.source ELSE cve_records.source END,
			metadata_json = CASE WHEN EXCLUDED.metadata_json <> '{}'::jsonb THEN EXCLUDED.metadata_json ELSE cve_records.metadata_json END,
			updated_at = NOW()
	`
	_, err := s.pool.Exec(ctx, q,
		record.CVEID,
		record.Title,
		record.Description,
		string(record.Severity),
		record.CVSSScore,
		record.PublishedAt,
		record.ModifiedAt,
		record.Rejected,
		record.KnownExploited,
		record.KEVDueDate,
		record.KEVVendorProject,
		record.KEVProduct,
		record.KEVRequiredAction,
		record.Source,
		jsonOrEmpty(record.MetadataJSON),
	)
	return err
}

func (s *PostgresStore) RecordSourceResult(ctx context.Context, result feed.SourceResult) error {
	const q = `
		INSERT INTO feed_source_status (
			source, last_success_at, last_attempt_at, last_error, records_processed, updated_at
		)
		VALUES ($1, CASE WHEN $3 = '' THEN NOW() ELSE NULL END, NOW(), $3, $2, NOW())
		ON CONFLICT (source) DO UPDATE SET
			last_success_at = CASE WHEN EXCLUDED.last_error = '' THEN EXCLUDED.last_attempt_at ELSE feed_source_status.last_success_at END,
			last_attempt_at = EXCLUDED.last_attempt_at,
			last_error = EXCLUDED.last_error,
			records_processed = EXCLUDED.records_processed,
			updated_at = NOW()
	`
	_, err := s.pool.Exec(ctx, q, result.Source, result.Records, result.Error)
	return err
}

func jsonOrEmpty(raw []byte) []byte {
	if len(raw) == 0 {
		raw, _ = json.Marshal(map[string]any{})
	}
	return raw
}
