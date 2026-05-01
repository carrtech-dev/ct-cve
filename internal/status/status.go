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

type OperationalLog struct {
	ID        int64     `json:"id"`
	Source    string    `json:"source,omitempty"`
	Category  string    `json:"category"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Detail    string    `json:"detail,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}
