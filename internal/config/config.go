package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr          string
	DatabaseURL       string
	FeedSyncInterval  time.Duration
	FeedSyncOnStartup bool
	FeedHTTPTimeout   time.Duration
	Sources           SourceConfig
}

type SourceConfig struct {
	NVD     NVDSourceConfig
	CISAKEV HTTPSourceConfig
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

	cfg := Config{
		HTTPAddr:          valueOrDefault(os.Getenv("CT_CVE_HTTP_ADDR"), ":8080"),
		DatabaseURL:       strings.TrimSpace(os.Getenv("CT_CVE_DATABASE_URL")),
		FeedSyncInterval:  feedSyncInterval,
		FeedSyncOnStartup: feedSyncOnStartup,
		FeedHTTPTimeout:   feedHTTPTimeout,
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
