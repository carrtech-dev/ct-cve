package feed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCISAKEVSourceFetchesAndParsesCatalog(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
		  "vulnerabilities": [
		    {
		      "cveID": " CVE-2026-1234 ",
		      "vendorProject": "OpenSSL",
		      "product": "OpenSSL",
		      "knownRansomwareCampaignUse": "Known",
		      "dueDate": "2026-05-01",
		      "requiredAction": "Apply updates"
		    },
		    {"cveID": "   "}
		  ]
		}`))
	}))
	t.Cleanup(server.Close)

	source := NewCISAKEVSource(server.URL, server.Client())
	result, err := source.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	records := result.Records

	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1: %#v", len(records), records)
	}
	record := records[0]
	if record.CVEID != "CVE-2026-1234" || !record.KnownExploited {
		t.Fatalf("unexpected record identity: %#v", record)
	}
	if record.Severity != SeverityUnknown || record.Source != SourceCISAKEV {
		t.Fatalf("severity/source = %q/%q, want unknown/%s", record.Severity, record.Source, SourceCISAKEV)
	}
	if record.KEVDueDate == nil || record.KEVDueDate.Format(time.DateOnly) != "2026-05-01" {
		t.Fatalf("KEVDueDate = %#v, want 2026-05-01", record.KEVDueDate)
	}
	if record.KEVVendorProject != "OpenSSL" || record.KEVProduct != "OpenSSL" || record.KEVRequiredAction != "Apply updates" {
		t.Fatalf("unexpected KEV metadata: %#v", record)
	}
}

func TestCISAKEVSourceRejectsNonOKStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "busy", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	source := NewCISAKEVSource(server.URL, server.Client())
	if _, err := source.Fetch(context.Background()); err == nil {
		t.Fatal("Fetch returned nil error, want status error")
	}
}
