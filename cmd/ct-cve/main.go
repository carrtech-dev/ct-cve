package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/carrtech-dev/ct-cve/internal/config"
	"github.com/carrtech-dev/ct-cve/internal/feed"
	"github.com/carrtech-dev/ct-cve/internal/store"
	"github.com/carrtech-dev/ct-cve/migrations"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	db, err := store.Open(context.Background(), cfg.DatabaseURL)
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	if err := db.Migrate(context.Background(), migrations.Files); err != nil {
		slog.Error("failed to apply database migrations", "error", err)
		os.Exit(1)
	}

	httpClient := &http.Client{Timeout: cfg.FeedHTTPTimeout}
	sources := make([]feed.Source, 0, 1)
	if cfg.Sources.CISAKEV.Enabled {
		sources = append(sources, feed.NewCISAKEVSource(cfg.Sources.CISAKEV.BaseURL, httpClient))
	}
	syncer := feed.Syncer{
		Store:   db,
		Sources: sources,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
	})

	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go syncer.Run(ctx, cfg.FeedSyncInterval, cfg.FeedSyncOnStartup)

	go func() {
		slog.Info("starting ct-cve service", "addr", cfg.HTTPAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("ct-cve service stopped unexpectedly", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("failed to stop ct-cve service cleanly", "error", err)
		os.Exit(1)
	}
}
