package config

import (
	"testing"
	"time"
)

func TestLoadRequiresDatabaseURL(t *testing.T) {
	t.Setenv("CT_CVE_DATABASE_URL", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load returned nil error, want missing database URL error")
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	t.Setenv("CT_CVE_DATABASE_URL", "postgres://ct_cve:ct_cve@localhost:5432/ct_cve?sslmode=disable")
	t.Setenv("CT_CVE_HTTP_ADDR", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Fatalf("HTTPAddr = %q, want :8080", cfg.HTTPAddr)
	}
	if cfg.FeedSyncInterval.String() != "6h0m0s" {
		t.Fatalf("FeedSyncInterval = %s, want 6h0m0s", cfg.FeedSyncInterval)
	}
	if !cfg.FeedSyncOnStartup {
		t.Fatal("FeedSyncOnStartup disabled by default, want enabled")
	}
	if cfg.FeedHTTPTimeout.String() != "30s" {
		t.Fatalf("FeedHTTPTimeout = %s, want 30s", cfg.FeedHTTPTimeout)
	}
	if !cfg.Sources.NVD.Enabled {
		t.Fatal("NVD source disabled by default, want enabled")
	}
	if cfg.Sources.NVD.BaseURL != "https://services.nvd.nist.gov/rest/json/cves/2.0" {
		t.Fatalf("NVD BaseURL = %q", cfg.Sources.NVD.BaseURL)
	}
	if cfg.Sources.NVD.RequestDelay.String() != "6s" {
		t.Fatalf("NVD RequestDelay = %s, want 6s without API key", cfg.Sources.NVD.RequestDelay)
	}
	if !cfg.Sources.CISAKEV.Enabled {
		t.Fatal("CISA KEV source disabled by default, want enabled")
	}
	if cfg.Sources.CISAKEV.BaseURL != "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" {
		t.Fatalf("CISA KEV BaseURL = %q", cfg.Sources.CISAKEV.BaseURL)
	}
}

func TestLoadParsesFeedSourceConfig(t *testing.T) {
	t.Setenv("CT_CVE_DATABASE_URL", "postgres://ct_cve:ct_cve@localhost:5432/ct_cve?sslmode=disable")
	t.Setenv("CT_CVE_FEED_SYNC_INTERVAL", "2h")
	t.Setenv("CT_CVE_FEED_SYNC_ON_STARTUP", "false")
	t.Setenv("CT_CVE_FEED_HTTP_TIMEOUT", "45s")
	t.Setenv("CT_CVE_NVD_API_KEY", "  test-key  ")
	t.Setenv("CT_CVE_NVD_REQUEST_DELAY", "750ms")
	t.Setenv("CT_CVE_NVD_BASE_URL", "https://nvd.example.test/cves")
	t.Setenv("CT_CVE_CISA_KEV_ENABLED", "false")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.FeedSyncInterval.String() != "2h0m0s" {
		t.Fatalf("FeedSyncInterval = %s, want 2h0m0s", cfg.FeedSyncInterval)
	}
	if cfg.FeedSyncOnStartup {
		t.Fatal("FeedSyncOnStartup enabled, want disabled")
	}
	if cfg.FeedHTTPTimeout.String() != "45s" {
		t.Fatalf("FeedHTTPTimeout = %s, want 45s", cfg.FeedHTTPTimeout)
	}
	if cfg.Sources.NVD.APIKey != "test-key" {
		t.Fatalf("NVD APIKey = %q, want trimmed key", cfg.Sources.NVD.APIKey)
	}
	if cfg.Sources.NVD.RequestDelay.String() != "750ms" {
		t.Fatalf("NVD RequestDelay = %s, want 750ms", cfg.Sources.NVD.RequestDelay)
	}
	if cfg.Sources.NVD.BaseURL != "https://nvd.example.test/cves" {
		t.Fatalf("NVD BaseURL = %q", cfg.Sources.NVD.BaseURL)
	}
	if cfg.Sources.CISAKEV.Enabled {
		t.Fatal("CISA KEV source enabled, want disabled")
	}
}

func TestLoadUsesShorterNVDDelayWhenAPIKeyIsConfigured(t *testing.T) {
	t.Setenv("CT_CVE_DATABASE_URL", "postgres://ct_cve:ct_cve@localhost:5432/ct_cve?sslmode=disable")
	t.Setenv("CT_CVE_NVD_API_KEY", "test-key")
	t.Setenv("CT_CVE_NVD_REQUEST_DELAY", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Sources.NVD.RequestDelay.String() != "600ms" {
		t.Fatalf("NVD RequestDelay = %s, want 600ms with API key", cfg.Sources.NVD.RequestDelay)
	}
}

func TestLoadRejectsInvalidSourceConfig(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{
			name: "invalid sync interval",
			env:  map[string]string{"CT_CVE_FEED_SYNC_INTERVAL": "soon"},
		},
		{
			name: "zero HTTP timeout",
			env:  map[string]string{"CT_CVE_FEED_HTTP_TIMEOUT": "0s"},
		},
		{
			name: "invalid sync on startup",
			env:  map[string]string{"CT_CVE_FEED_SYNC_ON_STARTUP": "sometimes"},
		},
		{
			name: "invalid NVD enabled flag",
			env:  map[string]string{"CT_CVE_NVD_ENABLED": "sometimes"},
		},
		{
			name: "invalid NVD URL",
			env:  map[string]string{"CT_CVE_NVD_BASE_URL": "file:///tmp/nvd.json"},
		},
		{
			name: "invalid CISA KEV URL",
			env:  map[string]string{"CT_CVE_CISA_KEV_BASE_URL": "://bad"},
		},
		{
			name: "zero NVD delay",
			env:  map[string]string{"CT_CVE_NVD_REQUEST_DELAY": "0s"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CT_CVE_DATABASE_URL", "postgres://ct_cve:ct_cve@localhost:5432/ct_cve?sslmode=disable")
			for key, value := range tt.env {
				t.Setenv(key, value)
			}

			if _, err := Load(); err == nil {
				t.Fatal("Load returned nil error, want invalid config error")
			}
		})
	}
}

func TestApplySourceSettingsOverridesEnvironmentDefaults(t *testing.T) {
	cfg := Config{
		Sources: SourceConfig{
			NVD: NVDSourceConfig{
				Enabled:      true,
				BaseURL:      "https://nvd.example.test/cves",
				APIKey:       "env-key",
				RequestDelay: 6 * time.Second,
			},
			CISAKEV: HTTPSourceConfig{
				Enabled: true,
				BaseURL: "https://cisa.example.test/kev.json",
			},
		},
	}

	next := cfg.ApplySourceSettings([]SourceSettings{
		{
			Source:       "nvd",
			Enabled:      false,
			BaseURL:      "https://nvd.override.test/cves",
			APIKey:       "stored-key",
			RequestDelay: 900 * time.Millisecond,
		},
		{
			Source:  "cisa-kev",
			Enabled: false,
			BaseURL: "https://cisa.override.test/kev.json",
		},
	})

	if next.Sources.NVD.Enabled {
		t.Fatal("NVD enabled after stored override, want disabled")
	}
	if next.Sources.NVD.BaseURL != "https://nvd.override.test/cves" {
		t.Fatalf("NVD BaseURL = %q", next.Sources.NVD.BaseURL)
	}
	if next.Sources.NVD.APIKey != "stored-key" {
		t.Fatalf("NVD APIKey = %q, want stored-key", next.Sources.NVD.APIKey)
	}
	if next.Sources.NVD.RequestDelay != 900*time.Millisecond {
		t.Fatalf("NVD RequestDelay = %s, want 900ms", next.Sources.NVD.RequestDelay)
	}
	if next.Sources.CISAKEV.Enabled {
		t.Fatal("CISA KEV enabled after stored override, want disabled")
	}
	if next.Sources.CISAKEV.BaseURL != "https://cisa.override.test/kev.json" {
		t.Fatalf("CISA KEV BaseURL = %q", next.Sources.CISAKEV.BaseURL)
	}
}

func TestEditableSourceValidation(t *testing.T) {
	if _, err := ValidateHTTPURL("ftp://example.test/feed"); err == nil {
		t.Fatal("ValidateHTTPURL accepted non-HTTP URL")
	}
	if _, err := ValidatePositiveDuration("0s", time.Hour); err == nil {
		t.Fatal("ValidatePositiveDuration accepted zero duration")
	}
	if _, err := ValidatePositiveDuration("2h", time.Hour); err == nil {
		t.Fatal("ValidatePositiveDuration accepted duration above max")
	}
}
