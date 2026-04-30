package gui

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/carrtech-dev/ct-cve/internal/config"
	"github.com/carrtech-dev/ct-cve/internal/status"
)

type Store interface {
	ListFeedSourceStatus(context.Context) ([]status.FeedSourceStatus, error)
	ListFeedSourceConfig(context.Context) ([]config.SourceSettings, error)
	UpsertFeedSourceConfig(context.Context, config.SourceSettings) error
}

type Handler struct {
	cfg   config.Config
	store Store
	now   func() time.Time
}

func NewHandler(cfg config.Config, store Store) Handler {
	return Handler{
		cfg:   cfg,
		store: store,
		now:   time.Now,
	}
}

func (h Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/", h.serveIndex)
	mux.HandleFunc("/status", h.serveIndex)
	mux.HandleFunc("/api/status", h.serveStatus)
	mux.HandleFunc("/sources/", h.serveSourceConfig)
}

func (h Handler) serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/status" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	overview, err := h.overview(r.Context())
	if err != nil {
		http.Error(w, "failed to load CT-CVE status", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == http.MethodHead {
		return
	}
	if err := pageTemplate.Execute(w, overview); err != nil {
		http.Error(w, "failed to render CT-CVE status", http.StatusInternalServerError)
	}
}

func (h Handler) serveStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	overview, err := h.overview(r.Context())
	if err != nil {
		http.Error(w, "failed to load CT-CVE status", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodHead {
		return
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(overview); err != nil {
		http.Error(w, "failed to encode CT-CVE status", http.StatusInternalServerError)
	}
}

func (h Handler) serveSourceConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	source := strings.TrimPrefix(r.URL.Path, "/sources/")
	if source != "nvd" && source != "cisa-kev" {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid source configuration form", http.StatusBadRequest)
		return
	}

	current, err := h.effectiveConfig(r.Context())
	if err != nil {
		http.Error(w, "failed to load CT-CVE source configuration", http.StatusInternalServerError)
		return
	}
	setting, err := sourceSettingFromForm(source, current, r.Form)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.store.UpsertFeedSourceConfig(r.Context(), setting); err != nil {
		http.Error(w, "failed to save CT-CVE source configuration", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/status", http.StatusSeeOther)
}

func (h Handler) overview(ctx context.Context) (Overview, error) {
	cfg, err := h.effectiveConfig(ctx)
	if err != nil {
		return Overview{}, err
	}
	statuses, err := h.store.ListFeedSourceStatus(ctx)
	if err != nil {
		return Overview{}, err
	}

	return Overview{
		Service: ServiceStatus{
			Name:          "CT-CVE",
			GeneratedAt:   h.now().UTC(),
			CTOpsRequired: true,
			ReportingNote: "Host findings and customer-facing vulnerability reports stay in CT Ops.",
		},
		FeedSync: FeedSyncConfig{
			Interval:      cfg.FeedSyncInterval.String(),
			SyncOnStartup: cfg.FeedSyncOnStartup,
			HTTPTimeout:   cfg.FeedHTTPTimeout.String(),
		},
		Sources: []SourceOverview{
			{
				ID:               "nvd",
				Name:             "NVD",
				Enabled:          cfg.Sources.NVD.Enabled,
				BaseURL:          cfg.Sources.NVD.BaseURL,
				APIKeyConfigured: cfg.Sources.NVD.APIKey != "",
				RequestDelay:     cfg.Sources.NVD.RequestDelay.String(),
				FeedSourceStatus: findStatus(statuses, "nvd"),
			},
			{
				ID:               "cisa-kev",
				Name:             "CISA KEV",
				Enabled:          cfg.Sources.CISAKEV.Enabled,
				BaseURL:          cfg.Sources.CISAKEV.BaseURL,
				FeedSourceStatus: findStatus(statuses, "cisa-kev"),
			},
		},
		Subscription: SubscriptionStatus{
			Status: "pending CT Ops connector",
			Note:   "CT-CVE subscription and licence validation will be supplied through the CT Ops integration.",
		},
	}, nil
}

func (h Handler) effectiveConfig(ctx context.Context) (config.Config, error) {
	settings, err := h.store.ListFeedSourceConfig(ctx)
	if err != nil {
		return config.Config{}, err
	}
	return h.cfg.ApplySourceSettings(settings), nil
}

func sourceSettingFromForm(source string, cfg config.Config, values url.Values) (config.SourceSettings, error) {
	enabled := values.Get("enabled") == "on"
	baseURL, err := config.ValidateHTTPURL(values.Get("base_url"))
	if err != nil {
		return config.SourceSettings{}, err
	}
	setting := config.SourceSettings{
		Source:  source,
		Enabled: enabled,
		BaseURL: baseURL,
	}
	switch source {
	case "nvd":
		setting.APIKey = cfg.Sources.NVD.APIKey
		if values.Get("clear_api_key") == "on" {
			setting.APIKey = ""
		}
		if newAPIKey := strings.TrimSpace(values.Get("api_key")); newAPIKey != "" {
			if len(newAPIKey) > 256 {
				return config.SourceSettings{}, errors.New("NVD API key must be 256 characters or fewer")
			}
			setting.APIKey = newAPIKey
		}
		requestDelay, err := config.ValidatePositiveDuration(values.Get("request_delay"), time.Hour)
		if err != nil {
			return config.SourceSettings{}, err
		}
		setting.RequestDelay = requestDelay
	case "cisa-kev":
		setting.APIKey = ""
	}
	return setting, nil
}

func findStatus(statuses []status.FeedSourceStatus, source string) *status.FeedSourceStatus {
	for i := range statuses {
		if statuses[i].Source == source {
			return &statuses[i]
		}
	}
	return nil
}

type Overview struct {
	Service      ServiceStatus      `json:"service"`
	FeedSync     FeedSyncConfig     `json:"feedSync"`
	Sources      []SourceOverview   `json:"sources"`
	Subscription SubscriptionStatus `json:"subscription"`
}

type ServiceStatus struct {
	Name          string    `json:"name"`
	GeneratedAt   time.Time `json:"generatedAt"`
	CTOpsRequired bool      `json:"ctOpsRequired"`
	ReportingNote string    `json:"reportingNote"`
}

type FeedSyncConfig struct {
	Interval      string `json:"interval"`
	SyncOnStartup bool   `json:"syncOnStartup"`
	HTTPTimeout   string `json:"httpTimeout"`
}

type SourceOverview struct {
	ID               string                   `json:"id"`
	Name             string                   `json:"name"`
	Enabled          bool                     `json:"enabled"`
	BaseURL          string                   `json:"baseUrl"`
	APIKeyConfigured bool                     `json:"apiKeyConfigured,omitempty"`
	RequestDelay     string                   `json:"requestDelay,omitempty"`
	FeedSourceStatus *status.FeedSourceStatus `json:"status,omitempty"`
}

type SubscriptionStatus struct {
	Status string `json:"status"`
	Note   string `json:"note"`
}

var pageTemplate = template.Must(template.New("status").Funcs(template.FuncMap{
	"sourceState": func(source SourceOverview) string {
		if !source.Enabled {
			return "Disabled"
		}
		if source.FeedSourceStatus == nil {
			return "Waiting"
		}
		if source.FeedSourceStatus.LastError != "" {
			return "Error"
		}
		return "Healthy"
	},
	"formatTime": func(value *time.Time) string {
		if value == nil {
			return "Never"
		}
		return value.UTC().Format(time.RFC3339)
	},
}).Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CT-CVE Status</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f8fa;
      --panel: #ffffff;
      --text: #1f2933;
      --muted: #52606d;
      --line: #d9e2ec;
      --accent: #0f766e;
      --warn: #b7791f;
      --error: #b42318;
      --ok: #047857;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    header {
      background: var(--panel);
      border-bottom: 1px solid var(--line);
      padding: 24px clamp(16px, 5vw, 48px);
    }
    main {
      display: grid;
      gap: 20px;
      padding: 24px clamp(16px, 5vw, 48px) 40px;
    }
    h1, h2, h3, p { margin: 0; }
    h1 { font-size: clamp(28px, 4vw, 42px); font-weight: 700; letter-spacing: 0; }
    h2 { font-size: 18px; margin-bottom: 12px; }
    h3 { font-size: 15px; }
    .subhead { color: var(--muted); margin-top: 6px; max-width: 780px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; }
    .panel, .source {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
    }
    .metric { display: grid; gap: 4px; }
    .label { color: var(--muted); font-size: 12px; text-transform: uppercase; }
    .value { font-size: 20px; font-weight: 650; overflow-wrap: anywhere; }
    .source { display: grid; gap: 14px; }
    .source-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }
    .badge {
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 3px 9px;
      font-size: 12px;
      font-weight: 650;
      white-space: nowrap;
    }
    .badge.Healthy { color: var(--ok); border-color: #a7f3d0; background: #ecfdf5; }
    .badge.Waiting { color: var(--warn); border-color: #fde68a; background: #fffbeb; }
    .badge.Error { color: var(--error); border-color: #fecaca; background: #fef2f2; }
    .badge.Disabled { color: var(--muted); background: #f1f5f9; }
    dl { display: grid; grid-template-columns: minmax(110px, 150px) 1fr; gap: 8px 12px; margin: 0; }
    dt { color: var(--muted); }
    dd { margin: 0; overflow-wrap: anywhere; }
    form { display: grid; gap: 12px; margin-top: 4px; }
    .field { display: grid; gap: 5px; }
    .check { display: flex; align-items: center; gap: 8px; color: var(--text); }
    input[type="url"], input[type="text"], input[type="password"] {
      width: 100%;
      min-height: 38px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px 10px;
      font: inherit;
      color: var(--text);
      background: #fff;
    }
    button {
      justify-self: start;
      border: 1px solid #0f766e;
      border-radius: 6px;
      background: var(--accent);
      color: #fff;
      min-height: 36px;
      padding: 7px 12px;
      font: inherit;
      font-weight: 650;
      cursor: pointer;
    }
    code {
      background: #eef2f7;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 2px 5px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
    }
    a { color: var(--accent); }
    @media (max-width: 620px) {
      dl { grid-template-columns: 1fr; gap: 2px 0; }
      dd { margin-bottom: 8px; }
      .source-head { display: grid; }
    }
  </style>
</head>
<body>
  <header>
    <h1>CT-CVE Status</h1>
    <p class="subhead">{{ .Service.ReportingNote }}</p>
  </header>
  <main>
    <section class="grid" aria-label="Service summary">
      <div class="panel metric">
        <span class="label">CT Ops dependency</span>
        <span class="value">{{ if .Service.CTOpsRequired }}Required{{ else }}Not required{{ end }}</span>
      </div>
      <div class="panel metric">
        <span class="label">Feed interval</span>
        <span class="value">{{ .FeedSync.Interval }}</span>
      </div>
      <div class="panel metric">
        <span class="label">Startup sync</span>
        <span class="value">{{ if .FeedSync.SyncOnStartup }}Enabled{{ else }}Disabled{{ end }}</span>
      </div>
      <div class="panel metric">
        <span class="label">Generated</span>
        <span class="value">{{ .Service.GeneratedAt.Format "15:04:05 UTC" }}</span>
      </div>
    </section>

    <section class="panel">
      <h2>Source Health</h2>
      <div class="grid">
        {{ range .Sources }}
          <article class="source">
            <div class="source-head">
              <div>
                <h3>{{ .Name }}</h3>
                <p class="subhead"><code>{{ .ID }}</code></p>
              </div>
              <span class="badge {{ sourceState . }}">{{ sourceState . }}</span>
            </div>
            <dl>
              <dt>Enabled</dt>
              <dd>{{ if .Enabled }}Yes{{ else }}No{{ end }}</dd>
              <dt>Endpoint</dt>
              <dd>{{ .BaseURL }}</dd>
              {{ if .RequestDelay }}
                <dt>Request delay</dt>
                <dd>{{ .RequestDelay }}</dd>
              {{ end }}
              {{ if eq .ID "nvd" }}
                <dt>API key</dt>
                <dd>{{ if .APIKeyConfigured }}Configured{{ else }}Not configured{{ end }}</dd>
              {{ end }}
              <dt>Last success</dt>
              <dd>{{ if .FeedSourceStatus }}{{ formatTime .FeedSourceStatus.LastSuccessAt }}{{ else }}Never{{ end }}</dd>
              <dt>Last attempt</dt>
              <dd>{{ if .FeedSourceStatus }}{{ formatTime .FeedSourceStatus.LastAttemptAt }}{{ else }}Never{{ end }}</dd>
              <dt>Records</dt>
              <dd>{{ if .FeedSourceStatus }}{{ .FeedSourceStatus.RecordsProcessed }}{{ else }}0{{ end }}</dd>
              <dt>Last error</dt>
              <dd>{{ if and .FeedSourceStatus .FeedSourceStatus.LastError }}{{ .FeedSourceStatus.LastError }}{{ else }}None{{ end }}</dd>
            </dl>
            <form method="post" action="/sources/{{ .ID }}">
              <label class="check">
                <input type="checkbox" name="enabled" {{ if .Enabled }}checked{{ end }}>
                Enabled
              </label>
              <label class="field">
                <span class="label">Endpoint</span>
                <input type="url" name="base_url" value="{{ .BaseURL }}" maxlength="2048" required>
              </label>
              {{ if eq .ID "nvd" }}
                <label class="field">
                  <span class="label">Request delay</span>
                  <input type="text" name="request_delay" value="{{ .RequestDelay }}" maxlength="16" required>
                </label>
                <label class="field">
                  <span class="label">New API key</span>
                  <input type="password" name="api_key" value="" maxlength="256" autocomplete="off">
                </label>
                <label class="check">
                  <input type="checkbox" name="clear_api_key">
                  Clear stored API key
                </label>
              {{ end }}
              <button type="submit">Save source</button>
            </form>
          </article>
        {{ end }}
      </div>
    </section>

    <section class="panel">
      <h2>Subscription</h2>
      <dl>
        <dt>Status</dt>
        <dd>{{ .Subscription.Status }}</dd>
        <dt>Note</dt>
        <dd>{{ .Subscription.Note }}</dd>
      </dl>
    </section>

    <section class="panel">
      <h2>API</h2>
      <p class="subhead">Read-only status is available at <a href="/api/status">/api/status</a>.</p>
    </section>
  </main>
</body>
</html>`))
