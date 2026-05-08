package ctops

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestInventorySnapshotEndpointMatchesAndDeliversFindings(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	inbound := ServiceToken{ID: "ctops-inventory", Secret: "ctops inventory signing secret 12345", OrgID: "org_123", Scopes: []ServiceTokenScope{ScopeInventoryWrite}}
	outbound := ServiceToken{ID: "ctcve-outbound", Secret: "ctcve outbound signing secret 12345", OrgID: "org_123", Scopes: []ServiceTokenScope{ScopeFindingsWrite, ScopeConnectionRead}}

	var delivered FindingBatch
	ctopsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/integrations/ct-cve/v1/finding-batches" {
			t.Fatalf("unexpected callback path %s", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		if _, err := VerifyServiceRequest(r.Context(), VerifyServiceRequestOptions{
			Method:        r.Method,
			Path:          r.URL.Path,
			Body:          body,
			Headers:       r.Header,
			RequiredScope: ScopeFindingsWrite,
			OrgID:         "org_123",
			Tokens:        []ServiceToken{outbound},
			NonceStore:    NewMemoryNonceStore(),
			Now:           now,
		}); err != nil {
			t.Fatalf("callback signature verification failed: %v", err)
		}
		if err := json.Unmarshal(body, &delivered); err != nil {
			t.Fatalf("Unmarshal callback: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":true,"batchId":"` + delivered.BatchID + `","findingsAccepted":1,"findingsRejected":0,"findingsSkipped":0}`))
	}))
	defer ctopsServer.Close()

	store := &fakeStore{
		result: InventorySnapshotResult{
			Accepted:         true,
			SnapshotID:       "inv_1",
			HostsAccepted:    1,
			PackagesAccepted: 1,
			RowsRejected:     0,
			NextAction:       "none",
		},
		findings: []Finding{{
			FindingID:         "ctcve_find_1",
			HostID:            "host_1",
			SoftwarePackageID: "pkg_1",
			CVEID:             "CVE-2026-12345",
			Status:            FindingStatusOpen,
			PackageName:       "openssl",
			InstalledVersion:  "3.0.13-0ubuntu3.2",
			FixedVersion:      "3.0.13-0ubuntu3.3",
			Source:            "ubuntu-osv",
			Severity:          "high",
			CVSSScore:         ptrFloat(8.1),
			KnownExploited:    false,
			Confidence:        "confirmed",
			MatchReason:       "installed version is below fixed version",
			FirstSeenAt:       now,
			LastSeenAt:        now,
			CVE: CVESummary{
				Title:       "OpenSSL vulnerability",
				Description: "Short normalized summary.",
				PublishedAt: &now,
				ModifiedAt:  &now,
			},
		}},
	}
	handler := NewHandler(HandlerOptions{
		Connections: []Connection{{
			Name:            "Primary CT Ops",
			OrgID:           "org_123",
			CTOpsBaseURL:    ctopsServer.URL,
			InventoryTokens: []ServiceToken{inbound},
			CTOpsToken:      outbound,
		}},
		Store:      store,
		HTTPClient: ctopsServer.Client(),
		Now:        func() time.Time { return now },
	})

	body := `{
		"contractVersion": "2026-04-30",
		"orgId": "org_123",
		"orgSlug": "acme",
		"snapshotId": "inv_1",
		"snapshotType": "full",
		"generatedAt": "2026-05-08T12:00:00Z",
		"cursor": null,
		"hosts": [{"hostId":"host_1","hostname":"web-01","status":"online","updatedAt":"2026-05-08T12:00:00Z"}],
		"packages": [{"softwarePackageId":"pkg_1","hostId":"host_1","name":"openssl","version":"3.0.13-0ubuntu3.2","source":"dpkg","firstSeenAt":"2026-05-08T11:00:00Z","lastSeenAt":"2026-05-08T12:00:00Z"}]
	}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/ct-ops/inventory-snapshots", strings.NewReader(body))
	request.Header = signedHeaders(http.MethodPost, "/api/v1/ct-ops/inventory-snapshots", body, inbound.ID, inbound.Secret, "snapshot-nonce", now)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.Register(http.NewServeMux()).ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", response.Code, response.Body.String())
	}
	var result InventorySnapshotResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("Unmarshal response: %v", err)
	}
	if !result.Accepted || result.NextAction != "none" {
		t.Fatalf("response = %#v", result)
	}
	if len(store.snapshots) != 1 || store.snapshots[0].SnapshotID != "inv_1" {
		t.Fatalf("stored snapshots = %#v", store.snapshots)
	}
	if delivered.OrgID != "org_123" || len(delivered.Findings) != 1 {
		t.Fatalf("delivered batch = %#v", delivered)
	}
	if delivered.Findings[0].CVEID != "CVE-2026-12345" || delivered.Findings[0].HostID != "host_1" {
		t.Fatalf("delivered finding = %#v", delivered.Findings[0])
	}
}

func TestInventorySnapshotEndpointReturnsRetryActionWhenCallbackFails(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	inbound := ServiceToken{ID: "ctops-inventory", Secret: "ctops inventory signing secret 12345", OrgID: "org_123", Scopes: []ServiceTokenScope{ScopeInventoryWrite}}
	outbound := ServiceToken{ID: "ctcve-outbound", Secret: "ctcve outbound signing secret 12345", OrgID: "org_123", Scopes: []ServiceTokenScope{ScopeFindingsWrite}}
	ctopsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer ctopsServer.Close()

	store := &fakeStore{
		result: InventorySnapshotResult{Accepted: true, SnapshotID: "inv_1", HostsAccepted: 1, PackagesAccepted: 1, NextAction: "none"},
		findings: []Finding{{
			FindingID: "ctcve_find_1", HostID: "host_1", SoftwarePackageID: "pkg_1", CVEID: "CVE-2026-12345",
			Status: FindingStatusOpen, PackageName: "openssl", InstalledVersion: "1", Source: "ubuntu-osv",
			Severity: "high", Confidence: "confirmed", FirstSeenAt: now, LastSeenAt: now,
		}},
	}
	handler := NewHandler(HandlerOptions{
		Connections: []Connection{{Name: "Primary CT Ops", OrgID: "org_123", CTOpsBaseURL: ctopsServer.URL, InventoryTokens: []ServiceToken{inbound}, CTOpsToken: outbound}},
		Store:       store,
		HTTPClient:  ctopsServer.Client(),
		Now:         func() time.Time { return now },
	})
	body := `{"contractVersion":"2026-04-30","orgId":"org_123","snapshotId":"inv_1","snapshotType":"full","generatedAt":"2026-05-08T12:00:00Z","hosts":[],"packages":[]}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/ct-ops/inventory-snapshots", strings.NewReader(body))
	request.Header = signedHeaders(http.MethodPost, "/api/v1/ct-ops/inventory-snapshots", body, inbound.ID, inbound.Secret, "snapshot-nonce", now)
	response := httptest.NewRecorder()

	handler.Register(http.NewServeMux()).ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", response.Code, response.Body.String())
	}
	var result InventorySnapshotResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("Unmarshal response: %v", err)
	}
	if result.NextAction != "retry_findings" {
		t.Fatalf("NextAction = %q, want retry_findings", result.NextAction)
	}
	if store.lastErrorCode != "finding_delivery_failed" {
		t.Fatalf("lastErrorCode = %q", store.lastErrorCode)
	}
}

func TestInventorySnapshotEndpointRejectsHostRowLimit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	inbound := ServiceToken{ID: "ctops-inventory", Secret: "ctops inventory signing secret 12345", OrgID: "org_123", Scopes: []ServiceTokenScope{ScopeInventoryWrite}}
	hosts := make([]string, 0, maxHosts+1)
	for i := 0; i < maxHosts+1; i++ {
		hosts = append(hosts, `{"hostId":"host_`+strconv.Itoa(i)+`","hostname":"web-`+strconv.Itoa(i)+`","status":"online","updatedAt":"2026-05-08T12:00:00Z"}`)
	}
	body := `{"contractVersion":"2026-04-30","orgId":"org_123","snapshotId":"inv_1","snapshotType":"full","generatedAt":"2026-05-08T12:00:00Z","hosts":[` + strings.Join(hosts, ",") + `],"packages":[]}`
	handler := NewHandler(HandlerOptions{
		Connections: []Connection{{Name: "Primary CT Ops", OrgID: "org_123", InventoryTokens: []ServiceToken{inbound}}},
		Store:       &fakeStore{},
		Now:         func() time.Time { return now },
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/ct-ops/inventory-snapshots", strings.NewReader(body))
	request.Header = signedHeaders(http.MethodPost, "/api/v1/ct-ops/inventory-snapshots", body, inbound.ID, inbound.Secret, "limit-nonce", now)
	response := httptest.NewRecorder()

	handler.Register(http.NewServeMux()).ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "hosts must contain at most 500 rows") {
		t.Fatalf("body = %s", response.Body.String())
	}
}

func TestConnectionHealthEndpointIsOrgScopedAndSigned(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	inbound := ServiceToken{ID: "ctops-health", Secret: "ctops health signing secret 123456789", OrgID: "org_123", Scopes: []ServiceTokenScope{ScopeConnectionRead}}
	store := &fakeStore{health: ConnectionHealth{Configured: true, Enabled: true, ContractVersion: ContractVersion}}
	handler := NewHandler(HandlerOptions{
		Connections: []Connection{{Name: "Primary CT Ops", OrgID: "org_123", InventoryTokens: []ServiceToken{inbound}}},
		Store:       store,
		Now:         func() time.Time { return now },
	})
	body := ""
	request := httptest.NewRequest(http.MethodGet, "/api/v1/ct-ops/connection-health?orgId=org_123", nil)
	request.Header = signedHeaders(http.MethodGet, "/api/v1/ct-ops/connection-health", body, inbound.ID, inbound.Secret, "health-nonce", now)
	response := httptest.NewRecorder()

	handler.Register(http.NewServeMux()).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", response.Code, response.Body.String())
	}
	if !store.healthRecorded {
		t.Fatal("health check was not recorded")
	}
}

type fakeStore struct {
	snapshots      []InventorySnapshot
	result         InventorySnapshotResult
	findings       []Finding
	health         ConnectionHealth
	lastErrorCode  string
	healthRecorded bool
}

func (s *fakeStore) RememberNonce(_ context.Context, _ string, _ string, _ time.Time, _ time.Time) (bool, error) {
	return true, nil
}

func (s *fakeStore) ApplyInventorySnapshot(_ context.Context, snapshot InventorySnapshot, _ time.Time) (InventorySnapshotApplyResult, error) {
	s.snapshots = append(s.snapshots, snapshot)
	return InventorySnapshotApplyResult{Response: s.result, Findings: s.findings}, nil
}

func (s *fakeStore) RecordFindingDelivery(_ context.Context, _ string, _ string, _ int) error {
	return nil
}

func (s *fakeStore) RecordConnectionError(_ context.Context, _ string, code string) error {
	s.lastErrorCode = code
	return nil
}

func (s *fakeStore) UpdateInventorySnapshotResponse(_ context.Context, _ string, _ string, result InventorySnapshotResult) error {
	s.result = result
	return nil
}

func (s *fakeStore) ConnectionHealth(_ context.Context, _ string) (ConnectionHealth, error) {
	return s.health, nil
}

func (s *fakeStore) RecordConnectionHealth(_ context.Context, _ string) error {
	s.healthRecorded = true
	return nil
}

func ptrFloat(value float64) *float64 {
	return &value
}
