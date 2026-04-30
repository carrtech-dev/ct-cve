package gui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/carrtech-dev/ct-cve/internal/config"
	"github.com/carrtech-dev/ct-cve/internal/status"
)

func TestStatusAPIExposesSourceHealthWithoutSecrets(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 30, 13, 0, 0, 0, time.UTC)
	lastSuccess := now.Add(-time.Hour)
	handler := NewHandler(testConfig(), staticStore{
		statuses: []status.FeedSourceStatus{
			{
				Source:           "nvd",
				LastSuccessAt:    &lastSuccess,
				LastAttemptAt:    &lastSuccess,
				RecordsProcessed: 42,
				UpdatedAt:        lastSuccess,
			},
		},
	})
	handler.now = func() time.Time { return now }

	mux := http.NewServeMux()
	handler.Register(mux)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/status", nil)

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	if strings.Contains(response.Body.String(), "super-secret") {
		t.Fatal("status response leaked the configured NVD API key")
	}

	var overview Overview
	if err := json.Unmarshal(response.Body.Bytes(), &overview); err != nil {
		t.Fatalf("Unmarshal status response: %v", err)
	}
	if !overview.Service.CTOpsRequired {
		t.Fatal("CT Ops dependency was not exposed")
	}
	if overview.Subscription.Status == "" {
		t.Fatal("subscription placeholder status was empty")
	}
	if len(overview.Sources) != 2 {
		t.Fatalf("sources length = %d, want NVD and CISA KEV", len(overview.Sources))
	}
	if !overview.Sources[0].APIKeyConfigured {
		t.Fatal("NVD API key configured flag was false")
	}
	if overview.Sources[0].FeedSourceStatus == nil || overview.Sources[0].FeedSourceStatus.RecordsProcessed != 42 {
		t.Fatalf("NVD status = %#v, want persisted status", overview.Sources[0].FeedSourceStatus)
	}
}

func TestStatusPageRendersOperationalOverview(t *testing.T) {
	t.Parallel()

	handler := NewHandler(testConfig(), staticStore{})
	mux := http.NewServeMux()
	handler.Register(mux)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/status", nil)

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{"CT-CVE Status", "Source Health", "NVD", "CISA KEV", "pending CT Ops connector"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page body missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "super-secret") {
		t.Fatal("status page leaked the configured NVD API key")
	}
}

func TestStatusAPIReportsStoreErrors(t *testing.T) {
	t.Parallel()

	handler := NewHandler(testConfig(), staticStore{err: errors.New("database unavailable")})
	mux := http.NewServeMux()
	handler.Register(mux)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/status", nil)

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", response.Code)
	}
}

func TestStatusRoutesRejectUnsupportedMethods(t *testing.T) {
	t.Parallel()

	handler := NewHandler(testConfig(), staticStore{})
	mux := http.NewServeMux()
	handler.Register(mux)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/status", nil)

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", response.Code)
	}
}

func testConfig() config.Config {
	return config.Config{
		HTTPAddr:          ":8080",
		DatabaseURL:       "postgres://ct_cve:ct_cve@localhost:5432/ct_cve?sslmode=disable",
		FeedSyncInterval:  6 * time.Hour,
		FeedSyncOnStartup: true,
		FeedHTTPTimeout:   30 * time.Second,
		Sources: config.SourceConfig{
			NVD: config.NVDSourceConfig{
				Enabled:      true,
				BaseURL:      "https://nvd.example.test/cves",
				APIKey:       "super-secret",
				RequestDelay: 600 * time.Millisecond,
			},
			CISAKEV: config.HTTPSourceConfig{
				Enabled: true,
				BaseURL: "https://cisa.example.test/kev.json",
			},
		},
	}
}

type staticStore struct {
	statuses []status.FeedSourceStatus
	err      error
}

func (s staticStore) ListFeedSourceStatus(context.Context) ([]status.FeedSourceStatus, error) {
	return s.statuses, s.err
}
