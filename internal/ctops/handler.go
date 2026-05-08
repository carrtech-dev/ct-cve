package ctops

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Store interface {
	NonceStore
	ApplyInventorySnapshot(context.Context, InventorySnapshot, time.Time) (InventorySnapshotApplyResult, error)
	RecordFindingDelivery(context.Context, string, string, int) error
	RecordConnectionError(context.Context, string, string) error
	UpdateInventorySnapshotResponse(context.Context, string, string, InventorySnapshotResult) error
	ConnectionHealth(context.Context, string) (ConnectionHealth, error)
	RecordConnectionHealth(context.Context, string) error
}

type HandlerOptions struct {
	Connections []Connection
	Store       Store
	HTTPClient  *http.Client
	Now         func() time.Time
}

type Handler struct {
	connections []Connection
	store       Store
	httpClient  *http.Client
	now         func() time.Time
}

const (
	inventoryPath        = "/api/v1/ct-ops/inventory-snapshots"
	connectionHealthPath = "/api/v1/ct-ops/connection-health"
	findingBatchPath     = "/api/integrations/ct-cve/v1/finding-batches"
	maxBodyBytes         = 25 * 1024 * 1024
	maxHosts             = 500
	maxPackages          = 25_000
	maxFindingsPerBatch  = 5_000
)

func NewHandler(opts HandlerOptions) Handler {
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return Handler{
		connections: opts.Connections,
		store:       opts.Store,
		httpClient:  client,
		now:         now,
	}
}

func (h Handler) Register(mux *http.ServeMux) http.Handler {
	mux.HandleFunc(inventoryPath, h.serveInventorySnapshot)
	mux.HandleFunc(connectionHealthPath, h.serveConnectionHealth)
	return mux
}

func (h Handler) serveInventorySnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		errorResponse(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", false)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes+1))
	if err != nil {
		errorResponse(w, http.StatusRequestEntityTooLarge, "payload_too_large", "CT-CVE inventory snapshot payload exceeds the 25 MiB limit.", false)
		return
	}
	if len(body) > maxBodyBytes {
		errorResponse(w, http.StatusRequestEntityTooLarge, "payload_too_large", "CT-CVE inventory snapshot payload exceeds the 25 MiB limit.", false)
		return
	}

	var snapshot InventorySnapshot
	if err := json.Unmarshal(body, &snapshot); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid_json", "CT-CVE inventory snapshot payload must be valid JSON.", false)
		return
	}
	if err := validateSnapshot(snapshot); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid_payload", err.Error(), false)
		return
	}
	connection, ok := h.connectionForOrg(snapshot.OrgID)
	if !ok || len(connection.InventoryTokens) == 0 {
		errorResponse(w, http.StatusForbidden, "unknown_org", "No CT Ops connection is configured for this organisation.", false)
		return
	}
	if _, err := VerifyServiceRequest(r.Context(), VerifyServiceRequestOptions{
		Method:        r.Method,
		Path:          r.URL.Path,
		Body:          body,
		Headers:       r.Header,
		RequiredScope: ScopeInventoryWrite,
		OrgID:         snapshot.OrgID,
		Tokens:        connection.InventoryTokens,
		NonceStore:    h.store,
		Now:           h.now(),
	}); err != nil {
		serviceError(w, err)
		return
	}

	applied, err := h.store.ApplyInventorySnapshot(r.Context(), snapshot, h.now().UTC())
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "inventory_snapshot_failed", "Failed to process CT Ops inventory snapshot.", true)
		return
	}
	result := applied.Response
	if result.NextAction == "" {
		result.NextAction = "none"
	}

	if len(applied.Findings) > 0 && !applied.Replayed {
		if err := h.deliverFindings(r.Context(), connection, applied.Findings); err != nil {
			_ = h.store.RecordConnectionError(r.Context(), snapshot.OrgID, "finding_delivery_failed")
			result.NextAction = "retry_findings"
		}
		_ = h.store.UpdateInventorySnapshotResponse(r.Context(), snapshot.OrgID, snapshot.SnapshotID, result)
	}

	writeJSON(w, http.StatusAccepted, result)
}

func (h Handler) serveConnectionHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		errorResponse(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", false)
		return
	}
	orgID := strings.TrimSpace(r.URL.Query().Get("orgId"))
	if orgID == "" {
		errorResponse(w, http.StatusBadRequest, "missing_org_id", "orgId query parameter is required.", false)
		return
	}
	connection, ok := h.connectionForOrg(orgID)
	if !ok || len(connection.InventoryTokens) == 0 {
		errorResponse(w, http.StatusForbidden, "unknown_org", "No CT Ops connection is configured for this organisation.", false)
		return
	}
	if _, err := VerifyServiceRequest(r.Context(), VerifyServiceRequestOptions{
		Method:        r.Method,
		Path:          r.URL.Path,
		Body:          nil,
		Headers:       r.Header,
		RequiredScope: ScopeConnectionRead,
		OrgID:         orgID,
		Tokens:        connection.InventoryTokens,
		NonceStore:    h.store,
		Now:           h.now(),
	}); err != nil {
		serviceError(w, err)
		return
	}
	if err := h.store.RecordConnectionHealth(r.Context(), orgID); err != nil {
		errorResponse(w, http.StatusInternalServerError, "connection_health_failed", "Failed to record CT Ops connection health.", true)
		return
	}
	health, err := h.store.ConnectionHealth(r.Context(), orgID)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "connection_health_failed", "Failed to load CT Ops connection health.", true)
		return
	}
	health.Configured = true
	health.ContractVersion = ContractVersion
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSON(w, http.StatusOK, health)
}

func (h Handler) connectionForOrg(orgID string) (Connection, bool) {
	for _, connection := range h.connections {
		if connection.OrgID == orgID {
			return connection, true
		}
	}
	return Connection{}, false
}

func (h Handler) deliverFindings(ctx context.Context, connection Connection, findings []Finding) error {
	if connection.CTOpsBaseURL == "" || connection.CTOpsToken.ID == "" {
		return fmt.Errorf("CT Ops callback token is not configured")
	}
	for start := 0; start < len(findings); start += maxFindingsPerBatch {
		end := start + maxFindingsPerBatch
		if end > len(findings) {
			end = len(findings)
		}
		batch := FindingBatch{
			ContractVersion: ContractVersion,
			OrgID:           connection.OrgID,
			BatchID:         batchID(connection.OrgID, h.now().UTC(), start/maxFindingsPerBatch),
			GeneratedAt:     h.now().UTC(),
			Findings:        findings[start:end],
		}
		body, err := json.Marshal(batch)
		if err != nil {
			return err
		}
		endpoint, err := callbackURL(connection.CTOpsBaseURL)
		if err != nil {
			return err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return err
		}
		headers := SignServiceRequest(SignServiceRequestOptions{
			Method:    http.MethodPost,
			Path:      findingBatchPath,
			Body:      body,
			Token:     connection.CTOpsToken,
			Timestamp: h.now().UTC(),
		})
		for key, values := range headers {
			for _, value := range values {
				request.Header.Add(key, value)
			}
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := h.httpClient.Do(request)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return fmt.Errorf("CT Ops finding callback returned HTTP %d", response.StatusCode)
		}
		if err := h.store.RecordFindingDelivery(ctx, connection.OrgID, batch.BatchID, len(batch.Findings)); err != nil {
			return err
		}
	}
	return nil
}

func validateSnapshot(snapshot InventorySnapshot) error {
	if snapshot.ContractVersion != ContractVersion {
		return fmt.Errorf("unsupported contractVersion")
	}
	if strings.TrimSpace(snapshot.OrgID) == "" {
		return fmt.Errorf("orgId is required")
	}
	if strings.TrimSpace(snapshot.SnapshotID) == "" {
		return fmt.Errorf("snapshotId is required")
	}
	if snapshot.SnapshotType != "full" && snapshot.SnapshotType != "incremental" && snapshot.SnapshotType != "tombstone" {
		return fmt.Errorf("snapshotType must be full, incremental, or tombstone")
	}
	if snapshot.GeneratedAt.IsZero() {
		return fmt.Errorf("generatedAt is required")
	}
	if len(snapshot.Hosts) > maxHosts {
		return fmt.Errorf("hosts must contain at most 500 rows")
	}
	if len(snapshot.Packages) > maxPackages {
		return fmt.Errorf("packages must contain at most 25000 rows")
	}
	for _, host := range snapshot.Hosts {
		if strings.TrimSpace(host.HostID) == "" || strings.TrimSpace(host.Hostname) == "" {
			return fmt.Errorf("hostId and hostname are required for every host")
		}
	}
	for _, pkg := range snapshot.Packages {
		if strings.TrimSpace(pkg.SoftwarePackageID) == "" || strings.TrimSpace(pkg.HostID) == "" || strings.TrimSpace(pkg.Name) == "" || strings.TrimSpace(pkg.Version) == "" || strings.TrimSpace(pkg.Source) == "" {
			return fmt.Errorf("softwarePackageId, hostId, name, version, and source are required for every package")
		}
		if pkg.FirstSeenAt.IsZero() || pkg.LastSeenAt.IsZero() {
			return fmt.Errorf("firstSeenAt and lastSeenAt are required for every package")
		}
	}
	return nil
}

func callbackURL(baseURL string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + findingBatchPath
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func batchID(orgID string, now time.Time, page int) string {
	compact := now.UTC().Format("20060102_150405")
	return fmt.Sprintf("findings_%s_%s_%d", compact, orgID, page)
}

func serviceError(w http.ResponseWriter, err error) {
	var authErr *ServiceAuthError
	if errorsAsServiceAuth(err, &authErr) {
		errorResponse(w, authErr.Status, authErr.Code, authErr.Message, authErr.Retryable)
		return
	}
	errorResponse(w, http.StatusInternalServerError, "service_auth_failed", "Failed to verify CT-CVE service request.", true)
}

func errorsAsServiceAuth(err error, target **ServiceAuthError) bool {
	return AsServiceAuthError(err, target)
}

func errorResponse(w http.ResponseWriter, status int, code, message string, retryable bool) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"code":      code,
			"message":   message,
			"retryable": retryable,
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
