package ctops

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type NonceStore interface {
	RememberNonce(ctx context.Context, tokenID, nonce string, expiresAt, now time.Time) (bool, error)
}

type ServiceAuthError struct {
	Code      string
	Message   string
	Retryable bool
	Status    int
}

func (e *ServiceAuthError) Error() string {
	return e.Message
}

type VerifyServiceRequestOptions struct {
	Method        string
	Path          string
	Body          []byte
	Headers       http.Header
	RequiredScope ServiceTokenScope
	OrgID         string
	Tokens        []ServiceToken
	NonceStore    NonceStore
	Now           time.Time
}

type VerifyServiceRequestResult struct {
	Token ServiceToken
}

type SignServiceRequestOptions struct {
	Method    string
	Path      string
	Body      []byte
	Token     ServiceToken
	Nonce     string
	Timestamp time.Time
}

const (
	authScheme      = "CT-ServiceToken"
	signaturePrefix = "v1="
	maxClockSkew    = 5 * time.Minute
	nonceTTL        = 10 * time.Minute
)

func AsServiceAuthError(err error, target **ServiceAuthError) bool {
	return errors.As(err, target)
}

func NewMemoryNonceStore() NonceStore {
	return &memoryNonceStore{seen: map[string]time.Time{}}
}

type memoryNonceStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (s *memoryNonceStore) RememberNonce(_ context.Context, tokenID, nonce string, expiresAt, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, expiry := range s.seen {
		if !expiry.After(now) {
			delete(s.seen, key)
		}
	}
	key := tokenID + ":" + nonce
	if _, ok := s.seen[key]; ok {
		return false, nil
	}
	s.seen[key] = expiresAt
	return true, nil
}

func VerifyServiceRequest(ctx context.Context, opts VerifyServiceRequestOptions) (VerifyServiceRequestResult, error) {
	auth := strings.TrimSpace(opts.Headers.Get("Authorization"))
	if auth == "" {
		return VerifyServiceRequestResult{}, authError("missing_authorization", http.StatusUnauthorized, "Missing CT-CVE service token authorization header.", false)
	}
	parts := strings.Fields(auth)
	if len(parts) != 2 || parts[0] != authScheme {
		return VerifyServiceRequestResult{}, authError("invalid_authorization", http.StatusUnauthorized, "Invalid CT-CVE service token authorization header.", false)
	}

	tokenID := parts[1]
	token, ok := findToken(opts.Tokens, tokenID)
	if !ok {
		return VerifyServiceRequestResult{}, authError("unknown_token", http.StatusUnauthorized, "CT-CVE service token was not found.", false)
	}
	if token.Revoked {
		return VerifyServiceRequestResult{}, authError("revoked_token", http.StatusUnauthorized, "CT-CVE service token is revoked.", false)
	}
	if !hasScope(token, opts.RequiredScope) {
		return VerifyServiceRequestResult{}, authError("insufficient_scope", http.StatusForbidden, "CT-CVE service token is not allowed to perform this action.", false)
	}
	if token.OrgID != opts.OrgID {
		return VerifyServiceRequestResult{}, authError("org_scope_mismatch", http.StatusForbidden, "CT-CVE service token is not scoped to the requested organisation.", false)
	}

	timestamp := opts.Headers.Get("X-CT-Timestamp")
	nonce := opts.Headers.Get("X-CT-Nonce")
	contentHash := opts.Headers.Get("X-CT-Content-SHA256")
	signatureHeader := opts.Headers.Get("X-CT-Signature")
	if timestamp == "" || nonce == "" || contentHash == "" || signatureHeader == "" {
		return VerifyServiceRequestResult{}, authError("missing_header", http.StatusUnauthorized, "Missing required CT-CVE service signature header.", false)
	}

	requestTime, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		requestTime, err = time.Parse(time.RFC3339Nano, timestamp)
	}
	if err != nil {
		return VerifyServiceRequestResult{}, authError("invalid_timestamp", http.StatusUnauthorized, "CT-CVE service timestamp is invalid.", false)
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	if absDuration(now.Sub(requestTime)) > maxClockSkew {
		return VerifyServiceRequestResult{}, authError("timestamp_out_of_range", http.StatusUnauthorized, "CT-CVE service timestamp is outside the allowed replay window.", false)
	}

	bodyHash := sha256Hex(opts.Body)
	if len(contentHash) != 64 || !safeEqual(contentHash, bodyHash) {
		return VerifyServiceRequestResult{}, authError("content_hash_mismatch", http.StatusUnauthorized, "CT-CVE service content hash does not match the request body.", false)
	}
	if !strings.HasPrefix(signatureHeader, signaturePrefix) {
		return VerifyServiceRequestResult{}, authError("invalid_signature", http.StatusUnauthorized, "CT-CVE service signature could not be verified.", false)
	}
	actualSignature := strings.TrimPrefix(signatureHeader, signaturePrefix)
	expectedSignature := signature(opts.Method, opts.Path, timestamp, nonce, bodyHash, token.Secret)
	if !safeEqual(actualSignature, expectedSignature) {
		return VerifyServiceRequestResult{}, authError("invalid_signature", http.StatusUnauthorized, "CT-CVE service signature could not be verified.", false)
	}

	if opts.NonceStore == nil {
		return VerifyServiceRequestResult{}, fmt.Errorf("nonce store is required")
	}
	remembered, err := opts.NonceStore.RememberNonce(ctx, token.ID, nonce, now.Add(nonceTTL), now)
	if err != nil {
		return VerifyServiceRequestResult{}, err
	}
	if !remembered {
		return VerifyServiceRequestResult{}, authError("replayed_nonce", http.StatusUnauthorized, "CT-CVE service nonce has already been used.", false)
	}

	return VerifyServiceRequestResult{Token: token}, nil
}

func SignServiceRequest(opts SignServiceRequestOptions) http.Header {
	timestamp := opts.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	nonce := opts.Nonce
	if nonce == "" {
		nonce = randomNonce()
	}
	bodyHash := sha256Hex(opts.Body)
	headers := http.Header{}
	headers.Set("Authorization", authScheme+" "+opts.Token.ID)
	headers.Set("X-CT-Timestamp", timestamp.UTC().Format(time.RFC3339))
	headers.Set("X-CT-Nonce", nonce)
	headers.Set("X-CT-Content-SHA256", bodyHash)
	headers.Set("X-CT-Signature", signaturePrefix+signature(opts.Method, opts.Path, headers.Get("X-CT-Timestamp"), nonce, bodyHash, opts.Token.Secret))
	return headers
}

func authError(code string, status int, message string, retryable bool) *ServiceAuthError {
	return &ServiceAuthError{Code: code, Status: status, Message: message, Retryable: retryable}
}

func findToken(tokens []ServiceToken, id string) (ServiceToken, bool) {
	for _, token := range tokens {
		if token.ID == id {
			return token, true
		}
	}
	return ServiceToken{}, false
}

func hasScope(token ServiceToken, scope ServiceTokenScope) bool {
	for _, candidate := range token.Scopes {
		if candidate == scope {
			return true
		}
	}
	return false
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func signature(method, path, timestamp, nonce, bodyHash, secret string) string {
	input := strings.Join([]string{strings.ToUpper(method), path, timestamp, nonce, bodyHash}, "\n")
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(input))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func safeEqual(a, b string) bool {
	left := []byte(a)
	right := []byte(b)
	return len(left) == len(right) && hmac.Equal(left, right)
}

func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

func randomNonce() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(raw[:])
}
