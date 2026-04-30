package feed

import (
	"context"
	"errors"
	"testing"
)

func TestSyncerPersistsEnabledSourcesAndRecordsStatus(t *testing.T) {
	t.Parallel()

	store := &recordingStore{}
	syncer := Syncer{
		Store: store,
		Sources: []Source{
			staticSource{
				id:      SourceCISAKEV,
				enabled: true,
				result: FetchResult{
					Records: []CVERecord{
						{CVEID: "CVE-2026-1234", KnownExploited: true, Source: SourceCISAKEV},
					},
					AffectedPackages: []AffectedPackage{
						{CVEID: "CVE-2026-1234", Source: "debian-tracker", DistroID: "debian", DistroCodename: "bookworm", PackageName: "openssl", FixedVersion: "3.0.11-1~deb12u2"},
					},
				},
			},
			staticSource{id: "disabled", enabled: false},
		},
	}

	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}

	if len(store.records) != 1 || store.records[0].CVEID != "CVE-2026-1234" {
		t.Fatalf("records = %#v, want persisted CISA record", store.records)
	}
	if len(store.affected) != 1 || store.affected[0].PackageName != "openssl" {
		t.Fatalf("affected = %#v, want persisted affected package", store.affected)
	}
	if len(store.results) != 1 || store.results[0].Source != SourceCISAKEV || store.results[0].Records != 1 || store.results[0].Error != "" {
		t.Fatalf("results = %#v, want successful CISA status", store.results)
	}
}

func TestSyncerRecordsSourceFailureAndContinues(t *testing.T) {
	t.Parallel()

	store := &recordingStore{}
	syncer := Syncer{
		Store: store,
		Sources: []Source{
			staticSource{id: SourceCISAKEV, enabled: true, err: errors.New("feed unavailable")},
			staticSource{
				id:      "second",
				enabled: true,
				result: FetchResult{
					Records: []CVERecord{
						{CVEID: "CVE-2026-9999", Source: "second"},
					},
				},
			},
		},
	}

	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}

	if len(store.records) != 1 || store.records[0].CVEID != "CVE-2026-9999" {
		t.Fatalf("records = %#v, want second source persisted", store.records)
	}
	if len(store.results) != 2 || store.results[0].Error == "" || store.results[1].Error != "" {
		t.Fatalf("results = %#v, want first failed and second successful", store.results)
	}
}

type staticSource struct {
	id      string
	enabled bool
	result  FetchResult
	err     error
}

func (s staticSource) ID() string {
	return s.id
}

func (s staticSource) Enabled() bool {
	return s.enabled
}

func (s staticSource) Fetch(context.Context) (FetchResult, error) {
	return s.result, s.err
}

type recordingStore struct {
	records  []CVERecord
	affected []AffectedPackage
	results  []SourceResult
}

func (s *recordingStore) UpsertCVERecords(_ context.Context, records []CVERecord) error {
	s.records = append(s.records, records...)
	return nil
}

func (s *recordingStore) UpsertAffectedPackages(_ context.Context, affected []AffectedPackage) error {
	s.affected = append(s.affected, affected...)
	return nil
}

func (s *recordingStore) RecordSourceResult(_ context.Context, result SourceResult) error {
	s.results = append(s.results, result)
	return nil
}
