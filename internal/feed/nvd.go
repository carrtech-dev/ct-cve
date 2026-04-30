package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const nvdResultsPerPage = 2000

type NVDSourceOptions struct {
	BaseURL      string
	APIKey       string
	RequestDelay time.Duration
	Lookback     time.Duration
	Now          func() time.Time
	Client       *http.Client
}

type NVDSource struct {
	baseURL      string
	apiKey       string
	requestDelay time.Duration
	lookback     time.Duration
	now          func() time.Time
	client       *http.Client
}

func NewNVDSource(opts NVDSourceOptions) NVDSource {
	if opts.Client == nil {
		opts.Client = http.DefaultClient
	}
	if opts.RequestDelay <= 0 {
		opts.RequestDelay = 6 * time.Second
	}
	if opts.Lookback <= 0 {
		opts.Lookback = 14 * 24 * time.Hour
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return NVDSource{
		baseURL:      strings.TrimSpace(opts.BaseURL),
		apiKey:       strings.TrimSpace(opts.APIKey),
		requestDelay: opts.RequestDelay,
		lookback:     opts.Lookback,
		now:          opts.Now,
		client:       opts.Client,
	}
}

func (s NVDSource) ID() string {
	return SourceNVD
}

func (s NVDSource) Enabled() bool {
	return s.baseURL != ""
}

func (s NVDSource) Fetch(ctx context.Context) (FetchResult, error) {
	end := s.now().UTC()
	start := end.Add(-s.lookback)
	base, err := url.Parse(s.baseURL)
	if err != nil {
		return FetchResult{}, err
	}
	values := base.Query()
	values.Set("lastModStartDate", nvdTime(start))
	values.Set("lastModEndDate", nvdTime(end))
	values.Set("resultsPerPage", fmt.Sprintf("%d", nvdResultsPerPage))

	total := 1
	startIndex := 0
	var records []CVERecord
	for startIndex < total {
		values.Set("startIndex", fmt.Sprintf("%d", startIndex))
		base.RawQuery = values.Encode()
		page, pageTotal, err := s.fetchPage(ctx, base.String())
		if err != nil {
			return FetchResult{}, err
		}
		total = pageTotal
		records = append(records, page...)
		startIndex += nvdResultsPerPage
		if startIndex < total {
			select {
			case <-ctx.Done():
				return FetchResult{}, ctx.Err()
			case <-time.After(s.requestDelay):
			}
		}
	}
	return FetchResult{Records: records}, nil
}

func (s NVDSource) fetchPage(ctx context.Context, pageURL string) ([]CVERecord, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	if s.apiKey != "" {
		req.Header.Set("apiKey", s.apiKey)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return nil, 0, fmt.Errorf("%s returned HTTP %d", SourceNVD, resp.StatusCode)
	}
	return ParseNVDAPI(resp.Body)
}

func ParseNVDAPI(r io.Reader) ([]CVERecord, int, error) {
	var doc struct {
		TotalResults    int `json:"totalResults"`
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				LastModified string `json:"lastModified"`
				VulnStatus   string `json:"vulnStatus"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics map[string][]struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, 0, err
	}

	records := make([]CVERecord, 0, len(doc.Vulnerabilities))
	for _, item := range doc.Vulnerabilities {
		cveID := strings.TrimSpace(item.CVE.ID)
		if cveID == "" {
			continue
		}
		record := CVERecord{
			CVEID:       cveID,
			Description: englishDescription(item.CVE.Descriptions),
			Severity:    SeverityUnknown,
			Rejected:    strings.EqualFold(item.CVE.VulnStatus, "Rejected"),
			Source:      SourceNVD,
		}
		if published := parseNVDTime(item.CVE.Published); published != nil {
			record.PublishedAt = published
		}
		if modified := parseNVDTime(item.CVE.LastModified); modified != nil {
			record.ModifiedAt = modified
		}
		if score, severity, ok := nvdBestMetric(item.CVE.Metrics); ok {
			record.CVSSScore = &score
			record.Severity = normalizeSeverity(severity)
		}
		records = append(records, record)
	}
	return records, doc.TotalResults, nil
}

func englishDescription(items []struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}) string {
	for _, item := range items {
		if item.Lang == "en" {
			return strings.TrimSpace(item.Value)
		}
	}
	if len(items) > 0 {
		return strings.TrimSpace(items[0].Value)
	}
	return ""
}

func nvdBestMetric(metrics map[string][]struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}) (float64, string, bool) {
	for _, key := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
		values := metrics[key]
		if len(values) > 0 {
			return values[0].CVSSData.BaseScore, values[0].CVSSData.BaseSeverity, true
		}
	}
	return 0, "", false
}

func parseNVDTime(value string) *time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil
	}
	return &t
}

func nvdTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func normalizeSeverity(value string) Severity {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return SeverityCritical
	case "high", "important":
		return SeverityHigh
	case "medium", "moderate":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "none", "negligible":
		return SeverityNone
	default:
		return SeverityUnknown
	}
}
