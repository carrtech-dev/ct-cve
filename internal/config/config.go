package config

import (
	"errors"
	"os"
	"strings"
)

type Config struct {
	HTTPAddr    string
	DatabaseURL string
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:    valueOrDefault(os.Getenv("CT_CVE_HTTP_ADDR"), ":8080"),
		DatabaseURL: strings.TrimSpace(os.Getenv("CT_CVE_DATABASE_URL")),
	}
	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("CT_CVE_DATABASE_URL is required")
	}
	return cfg, nil
}

func valueOrDefault(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
