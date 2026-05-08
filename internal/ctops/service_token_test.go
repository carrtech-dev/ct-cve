package ctops

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"
)

func signedHeaders(method, path, body, tokenID, secret, nonce string, now time.Time) http.Header {
	bodySum := sha256.Sum256([]byte(body))
	bodyHash := hex.EncodeToString(bodySum[:])
	timestamp := now.UTC().Format(time.RFC3339)
	input := strings.Join([]string{method, path, timestamp, nonce, bodyHash}, "\n")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(input))

	headers := http.Header{}
	headers.Set("Authorization", "CT-ServiceToken "+tokenID)
	headers.Set("X-CT-Timestamp", timestamp)
	headers.Set("X-CT-Nonce", nonce)
	headers.Set("X-CT-Content-SHA256", bodyHash)
	headers.Set("X-CT-Signature", "v1="+base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	return headers
}

func TestVerifyServiceRequestAcceptsSignedRequest(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	body := `{"orgId":"org_123"}`
	token := ServiceToken{
		ID:     "inventory-token",
		Secret: "ct-cve unit test signing secret 123456",
		OrgID:  "org_123",
		Scopes: []ServiceTokenScope{ScopeInventoryWrite},
	}

	result, err := VerifyServiceRequest(context.Background(), VerifyServiceRequestOptions{
		Method:        http.MethodPost,
		Path:          "/api/v1/ct-ops/inventory-snapshots",
		Body:          []byte(body),
		Headers:       signedHeaders(http.MethodPost, "/api/v1/ct-ops/inventory-snapshots", body, token.ID, token.Secret, "nonce-1", now),
		RequiredScope: ScopeInventoryWrite,
		OrgID:         "org_123",
		Tokens:        []ServiceToken{token},
		NonceStore:    NewMemoryNonceStore(),
		Now:           now,
	})

	if err != nil {
		t.Fatalf("VerifyServiceRequest returned error: %v", err)
	}
	if result.Token.ID != token.ID {
		t.Fatalf("token id = %q, want %q", result.Token.ID, token.ID)
	}
}

func TestVerifyServiceRequestRejectsBadHashWrongOrgScopeAndReplay(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	body := `{"orgId":"org_123"}`
	token := ServiceToken{
		ID:     "inventory-token",
		Secret: "ct-cve unit test signing secret 123456",
		OrgID:  "org_123",
		Scopes: []ServiceTokenScope{ScopeInventoryWrite},
	}
	nonceStore := NewMemoryNonceStore()

	tests := []struct {
		name    string
		body    []byte
		orgID   string
		scope   ServiceTokenScope
		headers http.Header
		code    string
	}{
		{
			name:    "bad body hash",
			body:    []byte(`{"orgId":"org_123","changed":true}`),
			orgID:   "org_123",
			scope:   ScopeInventoryWrite,
			headers: signedHeaders(http.MethodPost, "/api/v1/ct-ops/inventory-snapshots", body, token.ID, token.Secret, "nonce-bad-hash", now),
			code:    "content_hash_mismatch",
		},
		{
			name:    "wrong org",
			body:    []byte(body),
			orgID:   "org_other",
			scope:   ScopeInventoryWrite,
			headers: signedHeaders(http.MethodPost, "/api/v1/ct-ops/inventory-snapshots", body, token.ID, token.Secret, "nonce-wrong-org", now),
			code:    "org_scope_mismatch",
		},
		{
			name:    "wrong scope",
			body:    []byte(body),
			orgID:   "org_123",
			scope:   ScopeConnectionRead,
			headers: signedHeaders(http.MethodPost, "/api/v1/ct-ops/inventory-snapshots", body, token.ID, token.Secret, "nonce-wrong-scope", now),
			code:    "insufficient_scope",
		},
		{
			name:    "expired timestamp",
			body:    []byte(body),
			orgID:   "org_123",
			scope:   ScopeInventoryWrite,
			headers: signedHeaders(http.MethodPost, "/api/v1/ct-ops/inventory-snapshots", body, token.ID, token.Secret, "nonce-expired", now.Add(-6*time.Minute)),
			code:    "timestamp_out_of_range",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyServiceRequest(context.Background(), VerifyServiceRequestOptions{
				Method:        http.MethodPost,
				Path:          "/api/v1/ct-ops/inventory-snapshots",
				Body:          tt.body,
				Headers:       tt.headers,
				RequiredScope: tt.scope,
				OrgID:         tt.orgID,
				Tokens:        []ServiceToken{token},
				NonceStore:    nonceStore,
				Now:           now,
			})
			var authErr *ServiceAuthError
			if err == nil || !AsServiceAuthError(err, &authErr) {
				t.Fatalf("error = %v, want ServiceAuthError", err)
			}
			if authErr.Code != tt.code {
				t.Fatalf("code = %q, want %q", authErr.Code, tt.code)
			}
		})
	}

	headers := signedHeaders(http.MethodPost, "/api/v1/ct-ops/inventory-snapshots", body, token.ID, token.Secret, "nonce-replay", now)
	for attempt := 0; attempt < 2; attempt++ {
		_, err := VerifyServiceRequest(context.Background(), VerifyServiceRequestOptions{
			Method:        http.MethodPost,
			Path:          "/api/v1/ct-ops/inventory-snapshots",
			Body:          []byte(body),
			Headers:       headers,
			RequiredScope: ScopeInventoryWrite,
			OrgID:         "org_123",
			Tokens:        []ServiceToken{token},
			NonceStore:    nonceStore,
			Now:           now,
		})
		if attempt == 0 && err != nil {
			t.Fatalf("first replay setup request returned error: %v", err)
		}
		if attempt == 1 {
			var authErr *ServiceAuthError
			if err == nil || !AsServiceAuthError(err, &authErr) || authErr.Code != "replayed_nonce" {
				t.Fatalf("second replay error = %v, want replayed_nonce", err)
			}
		}
	}
}

func TestSignServiceRequestUsesCTOpsSignatureContract(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	body := []byte(`{"accepted":true}`)
	token := ServiceToken{
		ID:     "ct-cve-outbound",
		Secret: "ct-cve outbound signing secret 12345",
		OrgID:  "org_123",
		Scopes: []ServiceTokenScope{ScopeFindingsWrite, ScopeConnectionRead},
	}

	headers := SignServiceRequest(SignServiceRequestOptions{
		Method:    http.MethodPost,
		Path:      "/api/integrations/ct-cve/v1/finding-batches",
		Body:      body,
		Token:     token,
		Nonce:     "nonce-sign",
		Timestamp: now,
	})

	verified, err := VerifyServiceRequest(context.Background(), VerifyServiceRequestOptions{
		Method:        http.MethodPost,
		Path:          "/api/integrations/ct-cve/v1/finding-batches",
		Body:          bytes.Clone(body),
		Headers:       headers,
		RequiredScope: ScopeFindingsWrite,
		OrgID:         "org_123",
		Tokens:        []ServiceToken{token},
		NonceStore:    NewMemoryNonceStore(),
		Now:           now,
	})
	if err != nil {
		t.Fatalf("VerifyServiceRequest returned error for signed headers: %v", err)
	}
	if verified.Token.ID != token.ID {
		t.Fatalf("verified token = %q, want %q", verified.Token.ID, token.ID)
	}
}
