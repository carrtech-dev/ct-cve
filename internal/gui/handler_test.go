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

func TestStatusPageSavesEditableSourceConfiguration(t *testing.T) {
	t.Parallel()

	store := &recordingConfigStore{
		staticStore: staticStore{
			settings: []config.SourceSettings{
				{
					Source:       "nvd",
					Enabled:      true,
					BaseURL:      "https://nvd.example.test/cves",
					APIKey:       "existing-secret",
					RequestDelay: 600 * time.Millisecond,
				},
			},
		},
	}
	handler := NewHandler(testConfig(), store)
	mux := http.NewServeMux()
	handler.Register(mux)
	response := httptest.NewRecorder()
	body := strings.NewReader("enabled=on&base_url=https%3A%2F%2Fnvd2.example.test%2Fcves&request_delay=900ms&api_key=new-secret")
	request := httptest.NewRequest(http.MethodPost, "/sources/nvd", body)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Location"); got != "/status" {
		t.Fatalf("Location = %q, want /status", got)
	}
	if len(store.saved) != 1 {
		t.Fatalf("saved settings length = %d, want 1", len(store.saved))
	}
	saved := store.saved[0]
	if saved.Source != "nvd" || !saved.Enabled {
		t.Fatalf("saved source = %#v, want enabled NVD", saved)
	}
	if saved.BaseURL != "https://nvd2.example.test/cves" {
		t.Fatalf("saved BaseURL = %q", saved.BaseURL)
	}
	if saved.APIKey != "new-secret" {
		t.Fatalf("saved APIKey = %q, want new key", saved.APIKey)
	}
	if saved.RequestDelay != 900*time.Millisecond {
		t.Fatalf("saved RequestDelay = %s, want 900ms", saved.RequestDelay)
	}
}

func TestStatusPageKeepsExistingAPIKeyWhenSourceFormKeyIsBlank(t *testing.T) {
	t.Parallel()

	store := &recordingConfigStore{
		staticStore: staticStore{
			settings: []config.SourceSettings{
				{
					Source:       "nvd",
					Enabled:      true,
					BaseURL:      "https://nvd.example.test/cves",
					APIKey:       "existing-secret",
					RequestDelay: 600 * time.Millisecond,
				},
			},
		},
	}
	handler := NewHandler(testConfig(), store)
	mux := http.NewServeMux()
	handler.Register(mux)
	response := httptest.NewRecorder()
	body := strings.NewReader("enabled=on&base_url=https%3A%2F%2Fnvd.example.test%2Fcves&request_delay=600ms")
	request := httptest.NewRequest(http.MethodPost, "/sources/nvd", body)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", response.Code, response.Body.String())
	}
	if len(store.saved) != 1 || store.saved[0].APIKey != "existing-secret" {
		t.Fatalf("saved settings = %#v, want existing API key retained", store.saved)
	}
}

func TestStatusPageRejectsInvalidSourceConfiguration(t *testing.T) {
	t.Parallel()

	store := &recordingConfigStore{}
	handler := NewHandler(testConfig(), store)
	mux := http.NewServeMux()
	handler.Register(mux)
	response := httptest.NewRecorder()
	body := strings.NewReader("enabled=on&base_url=file%3A%2F%2F%2Ftmp%2Fnvd.json&request_delay=0s")
	request := httptest.NewRequest(http.MethodPost, "/sources/nvd", body)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
	if len(store.saved) != 0 {
		t.Fatalf("saved settings = %#v, want none", store.saved)
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
	settings []config.SourceSettings
	saved    []config.SourceSettings
	err      error
}

func (s staticStore) ListFeedSourceStatus(context.Context) ([]status.FeedSourceStatus, error) {
	return s.statuses, s.err
}

func (s staticStore) ListFeedSourceConfig(context.Context) ([]config.SourceSettings, error) {
	return s.settings, s.err
}

func (s staticStore) UpsertFeedSourceConfig(context.Context, config.SourceSettings) error {
	return errors.New("static store cannot save")
}

type recordingConfigStore struct {
	staticStore
	saved []config.SourceSettings
}

func (s *recordingConfigStore) UpsertFeedSourceConfig(_ context.Context, setting config.SourceSettings) error {
	s.saved = append(s.saved, setting)
	return nil
}
