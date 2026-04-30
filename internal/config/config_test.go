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
}
