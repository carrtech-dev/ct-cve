package config

import (
	"testing"

	"github.com/carrtech-dev/ct-cve/internal/ctops"
)

func TestLoadParsesCTOpsConnections(t *testing.T) {
	t.Setenv("CT_CVE_DATABASE_URL", "postgres://ct_cve:ct_cve@localhost:5432/ct_cve?sslmode=disable")
	t.Setenv("CT_CVE_CT_OPS_CONNECTIONS", `[
		{
			"name": "Primary CT Ops",
			"orgId": "org_123",
			"ctOpsBaseUrl": "https://ctops.example.test/",
			"inventoryTokens": [
				{
					"id": "ctops-inventory",
					"secret": "ctops inventory signing secret 12345",
					"scopes": ["inventory:write"]
				}
			],
			"ctOpsToken": {
				"id": "ctcve-outbound",
				"secret": "ctcve outbound signing secret 12345",
				"scopes": ["findings:write", "connection:read"]
			}
		}
	]`)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.CTOpsConnections) != 1 {
		t.Fatalf("connections = %d, want 1", len(cfg.CTOpsConnections))
	}
	connection := cfg.CTOpsConnections[0]
	if connection.Name != "Primary CT Ops" {
		t.Fatalf("Name = %q", connection.Name)
	}
	if connection.CTOpsBaseURL != "https://ctops.example.test" {
		t.Fatalf("CTOpsBaseURL = %q, want normalized URL", connection.CTOpsBaseURL)
	}
	if len(connection.InventoryTokens) != 1 || connection.InventoryTokens[0].Scopes[0] != ctops.ScopeInventoryWrite {
		t.Fatalf("InventoryTokens = %#v", connection.InventoryTokens)
	}
	if connection.CTOpsToken.ID != "ctcve-outbound" || len(connection.CTOpsToken.Scopes) != 2 {
		t.Fatalf("CTOpsToken = %#v", connection.CTOpsToken)
	}
}

func TestLoadRejectsInvalidCTOpsConnectionConfig(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "not json", value: `{nope`},
		{name: "missing org", value: `[{"name":"x","ctOpsBaseUrl":"https://ctops.example.test"}]`},
		{name: "non http url", value: `[{"name":"x","orgId":"org_123","ctOpsBaseUrl":"file:///tmp/x"}]`},
		{name: "weak token", value: `[{"name":"x","orgId":"org_123","ctOpsBaseUrl":"https://ctops.example.test","inventoryTokens":[{"id":"t","secret":"short","scopes":["inventory:write"]}]}]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CT_CVE_DATABASE_URL", "postgres://ct_cve:ct_cve@localhost:5432/ct_cve?sslmode=disable")
			t.Setenv("CT_CVE_CT_OPS_CONNECTIONS", tt.value)

			if _, err := Load(); err == nil {
				t.Fatal("Load returned nil error, want invalid CT Ops connection error")
			}
		})
	}
}
