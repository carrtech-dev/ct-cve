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

	"github.com/carrtech-dev/ct-cve/internal/auth"
	"github.com/carrtech-dev/ct-cve/internal/config"
	"github.com/carrtech-dev/ct-cve/internal/status"
)

func TestStatusPageRedirectsUnauthenticatedUsersToSignupWhenNoUsersExist(t *testing.T) {
	t.Parallel()

	handler := NewHandler(testConfig(), &recordingConfigStore{})
	mux := http.NewServeMux()
	handler.Register(mux)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/status", nil)

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Location"); got != "/signup" {
		t.Fatalf("Location = %q, want /signup", got)
	}
}

func TestStatusPageRedirectsUnauthenticatedUsersToLoginAfterBootstrap(t *testing.T) {
	t.Parallel()

	handler := NewHandler(testConfig(), &recordingConfigStore{users: []auth.User{{ID: 1, Username: "admin"}}})
	mux := http.NewServeMux()
	handler.Register(mux)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/status", nil)

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Location"); got != "/login" {
		t.Fatalf("Location = %q, want /login", got)
	}
}

func TestSignupCreatesFirstAdminAndSession(t *testing.T) {
	t.Parallel()

	store := &recordingConfigStore{}
	handler := NewHandler(testConfig(), store)
	mux := http.NewServeMux()
	handler.Register(mux)
	response := httptest.NewRecorder()
	body := strings.NewReader("username=admin&password=correct-horse-battery-staple&csrf_token=bootstrap")
	request := httptest.NewRequest(http.MethodPost, "/signup", body)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Location"); got != "/status" {
		t.Fatalf("Location = %q, want /status", got)
	}
	if len(store.users) != 1 {
		t.Fatalf("users length = %d, want 1", len(store.users))
	}
	if store.users[0].Username != "admin" || store.users[0].Role != auth.RoleAdmin {
		t.Fatalf("user = %#v, want admin user", store.users[0])
	}
	if store.users[0].PasswordHash == "correct-horse-battery-staple" || store.users[0].PasswordHash == "" {
		t.Fatalf("password hash was not stored securely: %q", store.users[0].PasswordHash)
	}
	if len(store.sessions) != 1 {
		t.Fatalf("sessions length = %d, want 1", len(store.sessions))
	}
	if cookie := response.Result().Cookies(); len(cookie) == 0 {
		t.Fatal("signup did not set a session cookie")
	}
}

func TestSignupIsHiddenAfterAdminExists(t *testing.T) {
	t.Parallel()

	handler := NewHandler(testConfig(), &recordingConfigStore{users: []auth.User{{ID: 1, Username: "admin"}}})
	mux := http.NewServeMux()
	handler.Register(mux)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/signup", nil)

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Location"); got != "/login" {
		t.Fatalf("Location = %q, want /login", got)
	}
}

func TestLoginCreatesSessionForExistingAdmin(t *testing.T) {
	t.Parallel()

	passwordHash, err := auth.HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	store := &recordingConfigStore{users: []auth.User{{ID: 1, Username: "admin", Role: auth.RoleAdmin, PasswordHash: passwordHash}}}
	handler := NewHandler(testConfig(), store)
	mux := http.NewServeMux()
	handler.Register(mux)
	response := httptest.NewRecorder()
	body := strings.NewReader("username=admin&password=correct-horse-battery-staple")
	request := httptest.NewRequest(http.MethodPost, "/login", body)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Location"); got != "/status" {
		t.Fatalf("Location = %q, want /status", got)
	}
	if len(store.sessions) != 1 {
		t.Fatalf("sessions length = %d, want 1", len(store.sessions))
	}
}

func TestStatusAPIExposesSourceHealthWithoutSecrets(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 30, 13, 0, 0, 0, time.UTC)
	lastSuccess := now.Add(-time.Hour)
	store := &recordingConfigStore{
		staticStore: staticStore{
			statuses: []status.FeedSourceStatus{
				{
					Source:           "nvd",
					LastSuccessAt:    &lastSuccess,
					LastAttemptAt:    &lastSuccess,
					RecordsProcessed: 42,
					UpdatedAt:        lastSuccess,
				},
			},
			logs: []status.OperationalLog{
				{
					ID:        99,
					Source:    "nvd",
					Category:  "feed",
					Level:     "info",
					Message:   "source sync completed",
					Detail:    "processed 42 CVE records",
					CreatedAt: lastSuccess,
				},
			},
		},
		users:    []auth.User{{ID: 1, Username: "admin", Role: auth.RoleAdmin}},
		sessions: []auth.Session{{TokenHash: auth.HashSessionToken("valid-token"), UserID: 1, CSRFToken: "csrf-token", ExpiresAt: now.Add(time.Hour)}},
	}
	handler := NewHandler(testConfig(), store)
	handler.now = func() time.Time { return now }

	mux := http.NewServeMux()
	handler.Register(mux)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "valid-token"})

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
	if len(overview.Logs) != 1 || overview.Logs[0].Message != "source sync completed" {
		t.Fatalf("logs = %#v, want recent operational log", overview.Logs)
	}
}

func TestStatusPageRendersOperationalOverview(t *testing.T) {
	t.Parallel()

	handler := NewHandler(testConfig(), authenticatedStore())
	mux := http.NewServeMux()
	handler.Register(mux)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/status", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "valid-token"})

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{"CT-CVE Status", "Source Health", "Activity Logs", "NVD", "CISA KEV", "pending CT Ops connector"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page body missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "super-secret") {
		t.Fatal("status page leaked the configured NVD API key")
	}
	if !strings.Contains(body, `name="csrf_token" value="csrf-token"`) {
		t.Fatal("status page did not include a CSRF token for configuration forms")
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
		users:    []auth.User{{ID: 1, Username: "admin", Role: auth.RoleAdmin}},
		sessions: []auth.Session{{TokenHash: auth.HashSessionToken("valid-token"), UserID: 1, CSRFToken: "csrf-token", ExpiresAt: time.Now().Add(time.Hour)}},
	}
	handler := NewHandler(testConfig(), store)
	mux := http.NewServeMux()
	handler.Register(mux)
	response := httptest.NewRecorder()
	body := strings.NewReader("enabled=on&base_url=https%3A%2F%2Fnvd2.example.test%2Fcves&request_delay=900ms&api_key=new-secret&csrf_token=csrf-token")
	request := httptest.NewRequest(http.MethodPost, "/sources/nvd", body)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "valid-token"})

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
	if len(store.logs) != 1 {
		t.Fatalf("logs length = %d, want 1", len(store.logs))
	}
	if strings.Contains(store.logs[0].Detail, "new-secret") {
		t.Fatal("source configuration log leaked the NVD API key")
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
		users:    []auth.User{{ID: 1, Username: "admin", Role: auth.RoleAdmin}},
		sessions: []auth.Session{{TokenHash: auth.HashSessionToken("valid-token"), UserID: 1, CSRFToken: "csrf-token", ExpiresAt: time.Now().Add(time.Hour)}},
	}
	handler := NewHandler(testConfig(), store)
	mux := http.NewServeMux()
	handler.Register(mux)
	response := httptest.NewRecorder()
	body := strings.NewReader("enabled=on&base_url=https%3A%2F%2Fnvd.example.test%2Fcves&request_delay=600ms&csrf_token=csrf-token")
	request := httptest.NewRequest(http.MethodPost, "/sources/nvd", body)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "valid-token"})

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

	store := authenticatedStore()
	handler := NewHandler(testConfig(), store)
	mux := http.NewServeMux()
	handler.Register(mux)
	response := httptest.NewRecorder()
	body := strings.NewReader("enabled=on&base_url=file%3A%2F%2F%2Ftmp%2Fnvd.json&request_delay=0s&csrf_token=csrf-token")
	request := httptest.NewRequest(http.MethodPost, "/sources/nvd", body)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "valid-token"})

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
	if len(store.saved) != 0 {
		t.Fatalf("saved settings = %#v, want none", store.saved)
	}
}

func TestStatusPageRejectsSourceConfigurationWithoutCSRF(t *testing.T) {
	t.Parallel()

	store := authenticatedStore()
	handler := NewHandler(testConfig(), store)
	mux := http.NewServeMux()
	handler.Register(mux)
	response := httptest.NewRecorder()
	body := strings.NewReader("enabled=on&base_url=https%3A%2F%2Fnvd.example.test%2Fcves&request_delay=600ms")
	request := httptest.NewRequest(http.MethodPost, "/sources/nvd", body)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "valid-token"})

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	if len(store.saved) != 0 {
		t.Fatalf("saved settings = %#v, want none", store.saved)
	}
}

func TestStatusAPIReportsStoreErrors(t *testing.T) {
	t.Parallel()

	handler := NewHandler(testConfig(), &recordingConfigStore{
		staticStore: staticStore{err: errors.New("database unavailable")},
		users:       []auth.User{{ID: 1, Username: "admin", Role: auth.RoleAdmin}},
		sessions:    []auth.Session{{TokenHash: auth.HashSessionToken("valid-token"), UserID: 1, CSRFToken: "csrf-token", ExpiresAt: time.Now().Add(time.Hour)}},
	})
	mux := http.NewServeMux()
	handler.Register(mux)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "valid-token"})

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", response.Code)
	}
}

func TestStatusRoutesRejectUnsupportedMethods(t *testing.T) {
	t.Parallel()

	handler := NewHandler(testConfig(), authenticatedStore())
	mux := http.NewServeMux()
	handler.Register(mux)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/status", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "valid-token"})

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", response.Code)
	}
}

func authenticatedStore() *recordingConfigStore {
	return &recordingConfigStore{
		users:    []auth.User{{ID: 1, Username: "admin", Role: auth.RoleAdmin}},
		sessions: []auth.Session{{TokenHash: auth.HashSessionToken("valid-token"), UserID: 1, CSRFToken: "csrf-token", ExpiresAt: time.Now().Add(time.Hour)}},
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
	logs     []status.OperationalLog
	saved    []config.SourceSettings
	err      error
}

func (s staticStore) ListFeedSourceStatus(context.Context) ([]status.FeedSourceStatus, error) {
	return s.statuses, s.err
}

func (s staticStore) ListFeedSourceConfig(context.Context) ([]config.SourceSettings, error) {
	return s.settings, s.err
}

func (s staticStore) ListOperationalLogs(context.Context, int) ([]status.OperationalLog, error) {
	return s.logs, s.err
}

func (s staticStore) UpsertFeedSourceConfig(context.Context, config.SourceSettings) error {
	return errors.New("static store cannot save")
}

func (s staticStore) RecordOperationalLog(context.Context, status.OperationalLog) error {
	return errors.New("static store cannot save")
}

type recordingConfigStore struct {
	staticStore
	users    []auth.User
	sessions []auth.Session
	saved    []config.SourceSettings
	logs     []status.OperationalLog
}

func (s *recordingConfigStore) UpsertFeedSourceConfig(_ context.Context, setting config.SourceSettings) error {
	s.saved = append(s.saved, setting)
	return nil
}

func (s *recordingConfigStore) RecordOperationalLog(_ context.Context, log status.OperationalLog) error {
	s.logs = append(s.logs, log)
	return nil
}

func (s *recordingConfigStore) CountUsers(context.Context) (int, error) {
	return len(s.users), s.err
}

func (s *recordingConfigStore) CreateUser(_ context.Context, user auth.NewUser) (auth.User, error) {
	if len(s.users) > 0 {
		return auth.User{}, auth.ErrUserExists
	}
	created := auth.User{
		ID:           int64(len(s.users) + 1),
		Username:     user.Username,
		PasswordHash: user.PasswordHash,
		Role:         user.Role,
		CreatedAt:    time.Now(),
	}
	s.users = append(s.users, created)
	return created, nil
}

func (s *recordingConfigStore) FindUserByUsername(_ context.Context, username string) (auth.User, error) {
	for _, user := range s.users {
		if user.Username == username {
			return user, nil
		}
	}
	return auth.User{}, auth.ErrUserNotFound
}

func (s *recordingConfigStore) CreateSession(_ context.Context, session auth.NewSession) error {
	s.sessions = append(s.sessions, auth.Session{
		TokenHash: session.TokenHash,
		UserID:    session.UserID,
		CSRFToken: session.CSRFToken,
		ExpiresAt: session.ExpiresAt,
	})
	return nil
}

func (s *recordingConfigStore) FindSession(_ context.Context, tokenHash string, now time.Time) (auth.Session, error) {
	for _, session := range s.sessions {
		if session.TokenHash == tokenHash && session.ExpiresAt.After(now) {
			return session, nil
		}
	}
	return auth.Session{}, auth.ErrSessionNotFound
}

func (s *recordingConfigStore) DeleteSession(_ context.Context, tokenHash string) error {
	next := s.sessions[:0]
	for _, session := range s.sessions {
		if session.TokenHash != tokenHash {
			next = append(next, session)
		}
	}
	s.sessions = next
	return nil
}
