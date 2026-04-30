package feed

import (
	"context"
	"log/slog"
	"time"
)

type Source interface {
	ID() string
	Enabled() bool
	Fetch(context.Context) (FetchResult, error)
}

type Store interface {
	UpsertCVERecords(context.Context, []CVERecord) error
	UpsertAffectedPackages(context.Context, []AffectedPackage) error
	RecordSourceResult(context.Context, SourceResult) error
}

type Syncer struct {
	Store   Store
	Sources []Source
}

func (s Syncer) SyncOnce(ctx context.Context) error {
	for _, source := range s.Sources {
		if !source.Enabled() {
			continue
		}
		fetched, err := source.Fetch(ctx)
		result := SourceResult{Source: source.ID(), Records: len(fetched.Records)}
		if err != nil {
			result.Error = err.Error()
			if recordErr := s.Store.RecordSourceResult(ctx, result); recordErr != nil {
				return recordErr
			}
			slog.Warn("feed source sync failed", "source", source.ID(), "error", err)
			continue
		}
		if err := s.Store.UpsertCVERecords(ctx, fetched.Records); err != nil {
			result.Error = err.Error()
			if recordErr := s.Store.RecordSourceResult(ctx, result); recordErr != nil {
				return recordErr
			}
			slog.Warn("feed source persistence failed", "source", source.ID(), "error", err)
			continue
		}
		if err := s.Store.UpsertAffectedPackages(ctx, fetched.AffectedPackages); err != nil {
			result.Error = err.Error()
			if recordErr := s.Store.RecordSourceResult(ctx, result); recordErr != nil {
				return recordErr
			}
			slog.Warn("feed source affected package persistence failed", "source", source.ID(), "error", err)
			continue
		}
		if err := s.Store.RecordSourceResult(ctx, result); err != nil {
			return err
		}
		slog.Info("feed source sync completed", "source", source.ID(), "records", len(fetched.Records), "affected_packages", len(fetched.AffectedPackages))
	}
	return nil
}

func (s Syncer) Run(ctx context.Context, interval time.Duration, syncOnStartup bool) {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	run := func() {
		if err := s.SyncOnce(ctx); err != nil {
			slog.Warn("feed sync cycle failed", "error", err)
		}
	}
	if syncOnStartup {
		go run()
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
