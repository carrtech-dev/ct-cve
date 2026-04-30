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
				records: []CVERecord{
					{CVEID: "CVE-2026-1234", KnownExploited: true, Source: SourceCISAKEV},
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
				records: []CVERecord{
					{CVEID: "CVE-2026-9999", Source: "second"},
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
	records []CVERecord
	err     error
}

func (s staticSource) ID() string {
	return s.id
}

func (s staticSource) Enabled() bool {
	return s.enabled
}

func (s staticSource) Fetch(context.Context) ([]CVERecord, error) {
	return s.records, s.err
}

type recordingStore struct {
	records []CVERecord
	results []SourceResult
}

func (s *recordingStore) UpsertCVERecords(_ context.Context, records []CVERecord) error {
	s.records = append(s.records, records...)
	return nil
}

func (s *recordingStore) RecordSourceResult(_ context.Context, result SourceResult) error {
	s.results = append(s.results, result)
	return nil
}
