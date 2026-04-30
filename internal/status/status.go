package status

import "time"

type FeedSourceStatus struct {
	Source           string     `json:"source"`
	LastSuccessAt    *time.Time `json:"lastSuccessAt,omitempty"`
	LastAttemptAt    *time.Time `json:"lastAttemptAt,omitempty"`
	LastError        string     `json:"lastError"`
	RecordsProcessed int        `json:"recordsProcessed"`
	UpdatedAt        time.Time  `json:"updatedAt"`
}
