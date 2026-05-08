package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/carrtech-dev/ct-cve/internal/ctops"
)

const serviceTokenMinBytes = 32

type rawCTOpsConnection struct {
	Name            string                 `json:"name"`
	OrgID           string                 `json:"orgId"`
	CTOpsBaseURL    string                 `json:"ctOpsBaseUrl"`
	InventoryTokens []rawCTOpsServiceToken `json:"inventoryTokens"`
	CTOpsToken      rawCTOpsServiceToken   `json:"ctOpsToken"`
}

type rawCTOpsServiceToken struct {
	ID      string   `json:"id"`
	Secret  string   `json:"secret"`
	Scopes  []string `json:"scopes"`
	Revoked bool     `json:"revoked"`
}

type Config struct {
	HTTPAddr          string
	DatabaseURL       string
	FeedSyncInterval  time.Duration
	FeedSyncOnStartup bool
	FeedHTTPTimeout   time.Duration
	Sources           SourceConfig
	CTOpsConnections  []ctops.Connection
}

type SourceConfig struct {
	NVD     NVDSourceConfig
	CISAKEV HTTPSourceConfig
}

type SourceSettings struct {
	Source       string
	Enabled      bool
	BaseURL      string
	APIKey       string
	RequestDelay time.Duration
}

type NVDSourceConfig struct {
	Enabled      bool
	BaseURL      string
	APIKey       string
	RequestDelay time.Duration
}

type HTTPSourceConfig struct {
	Enabled bool
	BaseURL string
}

func Load() (Config, error) {
	nvdAPIKey := strings.TrimSpace(os.Getenv("CT_CVE_NVD_API_KEY"))
	defaultNVDDelay := 6 * time.Second
	if nvdAPIKey != "" {
		defaultNVDDelay = 600 * time.Millisecond
	}

	feedSyncInterval, err := durationFromEnv("CT_CVE_FEED_SYNC_INTERVAL", 6*time.Hour)
	if err != nil {
		return Config{}, err
	}
	feedHTTPTimeout, err := durationFromEnv("CT_CVE_FEED_HTTP_TIMEOUT", 30*time.Second)
	if err != nil {
		return Config{}, err
	}
	feedSyncOnStartup, err := boolFromEnv("CT_CVE_FEED_SYNC_ON_STARTUP", true)
	if err != nil {
		return Config{}, err
	}
	nvdEnabled, err := boolFromEnv("CT_CVE_NVD_ENABLED", true)
	if err != nil {
		return Config{}, err
	}
	cisaKEVEnabled, err := boolFromEnv("CT_CVE_CISA_KEV_ENABLED", true)
	if err != nil {
		return Config{}, err
	}
	nvdRequestDelay, err := durationFromEnv("CT_CVE_NVD_REQUEST_DELAY", defaultNVDDelay)
	if err != nil {
		return Config{}, err
	}
	nvdBaseURL, err := httpURLFromEnv("CT_CVE_NVD_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
	if err != nil {
		return Config{}, err
	}
	cisaKEVBaseURL, err := httpURLFromEnv("CT_CVE_CISA_KEV_BASE_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
	if err != nil {
		return Config{}, err
	}
	ctOpsConnections, err := ctOpsConnectionsFromEnv(os.Getenv("CT_CVE_CT_OPS_CONNECTIONS"))
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		HTTPAddr:          valueOrDefault(os.Getenv("CT_CVE_HTTP_ADDR"), ":8080"),
		DatabaseURL:       strings.TrimSpace(os.Getenv("CT_CVE_DATABASE_URL")),
		FeedSyncInterval:  feedSyncInterval,
		FeedSyncOnStartup: feedSyncOnStartup,
		FeedHTTPTimeout:   feedHTTPTimeout,
		CTOpsConnections:  ctOpsConnections,
		Sources: SourceConfig{
			NVD: NVDSourceConfig{
				Enabled:      nvdEnabled,
				BaseURL:      nvdBaseURL,
				APIKey:       nvdAPIKey,
				RequestDelay: nvdRequestDelay,
			},
			CISAKEV: HTTPSourceConfig{
				Enabled: cisaKEVEnabled,
				BaseURL: cisaKEVBaseURL,
			},
		},
	}
	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("CT_CVE_DATABASE_URL is required")
	}
	return cfg, nil
}

func ctOpsConnectionsFromEnv(value string) ([]ctops.Connection, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var raw []rawCTOpsConnection
	if err := json.Unmarshal([]byte(value), &raw); err != nil {
		return nil, fmt.Errorf("CT_CVE_CT_OPS_CONNECTIONS must be valid JSON: %w", err)
	}
	connections := make([]ctops.Connection, 0, len(raw))
	for index, entry := range raw {
		path := fmt.Sprintf("CT_CVE_CT_OPS_CONNECTIONS[%d]", index)
		name := strings.TrimSpace(entry.Name)
		orgID := strings.TrimSpace(entry.OrgID)
		if name == "" || orgID == "" {
			return nil, fmt.Errorf("%s must include name and orgId", path)
		}
		baseURL, err := normalizeBaseURL(entry.CTOpsBaseURL, path+".ctOpsBaseUrl")
		if err != nil {
			return nil, err
		}
		inventoryTokens := make([]ctops.ServiceToken, 0, len(entry.InventoryTokens))
		for tokenIndex, rawToken := range entry.InventoryTokens {
			token, err := parseServiceToken(rawToken, orgID, fmt.Sprintf("%s.inventoryTokens[%d]", path, tokenIndex))
			if err != nil {
				return nil, err
			}
			inventoryTokens = append(inventoryTokens, token)
		}
		if len(inventoryTokens) == 0 {
			return nil, fmt.Errorf("%s.inventoryTokens must include at least one token", path)
		}
		ctOpsToken, err := parseServiceToken(entry.CTOpsToken, orgID, path+".ctOpsToken")
		if err != nil {
			return nil, err
		}
		connections = append(connections, ctops.Connection{
			Name:            name,
			OrgID:           orgID,
			CTOpsBaseURL:    baseURL,
			InventoryTokens: inventoryTokens,
			CTOpsToken:      ctOpsToken,
		})
	}
	return connections, nil
}

func parseServiceToken(raw rawCTOpsServiceToken, orgID, path string) (ctops.ServiceToken, error) {
	id := strings.TrimSpace(raw.ID)
	if id == "" || raw.Secret == "" {
		return ctops.ServiceToken{}, fmt.Errorf("%s must include id and secret", path)
	}
	if !secretHasEnoughEntropy(raw.Secret) {
		return ctops.ServiceToken{}, fmt.Errorf("%s.secret must contain at least 32 bytes of entropy", path)
	}
	scopes := make([]ctops.ServiceTokenScope, 0, len(raw.Scopes))
	for _, rawScope := range raw.Scopes {
		scope := ctops.ServiceTokenScope(strings.TrimSpace(rawScope))
		switch scope {
		case ctops.ScopeInventoryWrite, ctops.ScopeFindingsWrite, ctops.ScopeConnectionRead:
			scopes = append(scopes, scope)
		default:
			return ctops.ServiceToken{}, fmt.Errorf("%s.scopes contains unsupported scope %q", path, rawScope)
		}
	}
	if len(scopes) == 0 {
		return ctops.ServiceToken{}, fmt.Errorf("%s.scopes must include at least one scope", path)
	}
	return ctops.ServiceToken{
		ID:      id,
		Secret:  raw.Secret,
		OrgID:   orgID,
		Scopes:  scopes,
		Revoked: raw.Revoked,
	}, nil
}

func normalizeBaseURL(value, name string) (string, error) {
	parsedURL, err := validateHTTPURL(name, strings.TrimSpace(value))
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(parsedURL)
	if err != nil {
		return "", err
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func secretHasEnoughEntropy(value string) bool {
	return len(value) >= serviceTokenMinBytes
}

func (cfg Config) ApplySourceSettings(settings []SourceSettings) Config {
	next := cfg
	for _, setting := range settings {
		switch setting.Source {
		case "nvd":
			next.Sources.NVD.Enabled = setting.Enabled
			if setting.BaseURL != "" {
				next.Sources.NVD.BaseURL = setting.BaseURL
			}
			next.Sources.NVD.APIKey = setting.APIKey
			if setting.RequestDelay > 0 {
				next.Sources.NVD.RequestDelay = setting.RequestDelay
			}
		case "cisa-kev":
			next.Sources.CISAKEV.Enabled = setting.Enabled
			if setting.BaseURL != "" {
				next.Sources.CISAKEV.BaseURL = setting.BaseURL
			}
		}
	}
	return next
}

func ValidateHTTPURL(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) > 2048 {
		return "", errors.New("source URL must be 2048 characters or fewer")
	}
	return validateHTTPURL("source URL", trimmed)
}

func ValidatePositiveDuration(value string, max time.Duration) (time.Duration, error) {
	parsed, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil {
		return 0, errors.New("duration must be valid")
	}
	if parsed <= 0 {
		return 0, errors.New("duration must be greater than zero")
	}
	if max > 0 && parsed > max {
		return 0, fmt.Errorf("duration must be no greater than %s", max)
	}
	return parsed, nil
}

func valueOrDefault(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func boolFromEnv(name string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", name)
	}
	return parsed, nil
}

func durationFromEnv(name string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid duration", name)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", name)
	}
	return parsed, nil
}

func httpURLFromEnv(name string, fallback string) (string, error) {
	rawValue := valueOrDefault(os.Getenv(name), fallback)
	return validateHTTPURL(name, rawValue)
}

func validateHTTPURL(name string, rawValue string) (string, error) {
	parsed, err := url.Parse(rawValue)
	if err != nil {
		return "", fmt.Errorf("%s must be a valid URL", name)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("%s must use http or https", name)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("%s must include a host", name)
	}
	return rawValue, nil
}
