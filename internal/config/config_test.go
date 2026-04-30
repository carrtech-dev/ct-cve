package config

import "testing"

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
