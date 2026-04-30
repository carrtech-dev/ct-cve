package feed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseNVDAPIMapsCVERecords(t *testing.T) {
	t.Parallel()

	doc := `{
	  "totalResults": 1,
	  "vulnerabilities": [{
	    "cve": {
	      "id": " CVE-2026-1234 ",
	      "published": "2026-04-01T10:00:00.000Z",
	      "lastModified": "2026-04-02T11:00:00.000Z",
	      "vulnStatus": "Analyzed",
	      "descriptions": [
	        {"lang": "es", "value": "Spanish"},
	        {"lang": "en", "value": "OpenSSL vulnerability"}
	      ],
	      "metrics": {
	        "cvssMetricV31": [{
	          "cvssData": {
	            "baseScore": 8.8,
	            "baseSeverity": "HIGH"
	          }
	        }]
	      }
	    }
	  }]
	}`

	records, total, err := ParseNVDAPI(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("ParseNVDAPI: %v", err)
	}

	if total != 1 || len(records) != 1 {
		t.Fatalf("total=%d len(records)=%d, want 1 and 1", total, len(records))
	}
	record := records[0]
	if record.CVEID != "CVE-2026-1234" || record.Source != SourceNVD {
		t.Fatalf("identity = %q/%q, want CVE-2026-1234/%s", record.CVEID, record.Source, SourceNVD)
	}
	if record.Description != "OpenSSL vulnerability" || record.Severity != SeverityHigh {
		t.Fatalf("description/severity = %q/%q", record.Description, record.Severity)
	}
	if record.CVSSScore == nil || *record.CVSSScore != 8.8 {
		t.Fatalf("CVSSScore = %#v, want 8.8", record.CVSSScore)
	}
	if record.PublishedAt == nil || record.PublishedAt.UTC().Format(time.RFC3339) != "2026-04-01T10:00:00Z" {
		t.Fatalf("PublishedAt = %#v", record.PublishedAt)
	}
	if record.ModifiedAt == nil || record.ModifiedAt.UTC().Format(time.RFC3339) != "2026-04-02T11:00:00Z" {
		t.Fatalf("ModifiedAt = %#v", record.ModifiedAt)
	}
}

func TestParseNVDAPIMarksRejectedCVE(t *testing.T) {
	t.Parallel()

	doc := `{
	  "totalResults": 1,
	  "vulnerabilities": [{
	    "cve": {
	      "id": "CVE-2026-9999",
	      "vulnStatus": "Rejected",
	      "descriptions": [{"lang": "en", "value": "Rejected"}]
	    }
	  }]
	}`

	records, _, err := ParseNVDAPI(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("ParseNVDAPI: %v", err)
	}
	if len(records) != 1 || !records[0].Rejected || records[0].Severity != SeverityUnknown {
		t.Fatalf("records = %#v, want rejected unknown-severity record", records)
	}
}

func TestNVDSourceFetchesPagesWithAPIKeyAndDateWindow(t *testing.T) {
	t.Parallel()

	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("apiKey"); got != "test-key" {
			t.Fatalf("apiKey header = %q, want test-key", got)
		}
		if r.URL.Query().Get("lastModStartDate") != "2026-04-16T12:00:00.000Z" {
			t.Fatalf("lastModStartDate = %q", r.URL.Query().Get("lastModStartDate"))
		}
		if r.URL.Query().Get("lastModEndDate") != "2026-04-30T12:00:00.000Z" {
			t.Fatalf("lastModEndDate = %q", r.URL.Query().Get("lastModEndDate"))
		}
		requests = append(requests, r.URL.Query().Get("startIndex"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("startIndex") {
		case "0":
			_, _ = w.Write([]byte(`{"totalResults":2001,"vulnerabilities":[{"cve":{"id":"CVE-2026-0001","descriptions":[{"lang":"en","value":"first"}]}}]}`))
		case "2000":
			_, _ = w.Write([]byte(`{"totalResults":2001,"vulnerabilities":[{"cve":{"id":"CVE-2026-0002","descriptions":[{"lang":"en","value":"second"}]}}]}`))
		default:
			t.Fatalf("unexpected startIndex %q", r.URL.Query().Get("startIndex"))
		}
	}))
	t.Cleanup(server.Close)

	source := NewNVDSource(NVDSourceOptions{
		BaseURL:      server.URL,
		APIKey:       "test-key",
		RequestDelay: time.Millisecond,
		Lookback:     14 * 24 * time.Hour,
		Now:          func() time.Time { return time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC) },
		Client:       server.Client(),
	})

	records, err := source.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(records) != 2 || records[0].CVEID != "CVE-2026-0001" || records[1].CVEID != "CVE-2026-0002" {
		t.Fatalf("records = %#v, want two paged NVD records", records)
	}
	if got := strings.Join(requests, ","); got != "0,2000" {
		t.Fatalf("start indexes = %s, want 0,2000", got)
	}
}

func TestNVDSourceRejectsNonOKStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	t.Cleanup(server.Close)

	source := NewNVDSource(NVDSourceOptions{
		BaseURL:      server.URL,
		RequestDelay: time.Millisecond,
		Client:       server.Client(),
	})
	if _, err := source.Fetch(context.Background()); err == nil {
		t.Fatal("Fetch returned nil error, want status error")
	}
}
