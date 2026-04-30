package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type CISAKEVSource struct {
	baseURL string
	client  *http.Client
}

func NewCISAKEVSource(baseURL string, client *http.Client) CISAKEVSource {
	if client == nil {
		client = http.DefaultClient
	}
	return CISAKEVSource{
		baseURL: strings.TrimSpace(baseURL),
		client:  client,
	}
}

func (s CISAKEVSource) ID() string {
	return SourceCISAKEV
}

func (s CISAKEVSource) Enabled() bool {
	return s.baseURL != ""
}

func (s CISAKEVSource) Fetch(ctx context.Context) ([]CVERecord, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("%s returned HTTP %d", SourceCISAKEV, resp.StatusCode)
	}
	return ParseCISAKEV(resp.Body)
}

func ParseCISAKEV(r io.Reader) ([]CVERecord, error) {
	var doc struct {
		Vulnerabilities []struct {
			CVEID                      string `json:"cveID"`
			VendorProject              string `json:"vendorProject"`
			Product                    string `json:"product"`
			KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
			DueDate                    string `json:"dueDate"`
			RequiredAction             string `json:"requiredAction"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, err
	}

	records := make([]CVERecord, 0, len(doc.Vulnerabilities))
	for _, vuln := range doc.Vulnerabilities {
		cveID := strings.TrimSpace(vuln.CVEID)
		if cveID == "" {
			continue
		}
		var dueDate *time.Time
		if vuln.DueDate != "" {
			if parsed, err := time.Parse(time.DateOnly, vuln.DueDate); err == nil {
				dueDate = &parsed
			}
		}
		records = append(records, CVERecord{
			CVEID:             cveID,
			Severity:          SeverityUnknown,
			KnownExploited:    true,
			KEVDueDate:        dueDate,
			KEVVendorProject:  strings.TrimSpace(vuln.VendorProject),
			KEVProduct:        strings.TrimSpace(vuln.Product),
			KEVRequiredAction: strings.TrimSpace(vuln.RequiredAction),
			Source:            SourceCISAKEV,
		})
	}
	return records, nil
}
