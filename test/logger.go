package test

import (
	"log/slog"
	"os"
)

// NewLogger returns a *slog.Logger suitable for use in tests. Output goes to
// io.Discard by default; set TEST_LOGS=1 (info), 2 (debug), or 3 (trace) to
// stream output to stderr for local debugging.
func NewLogger() *slog.Logger {
	v := os.Getenv("TEST_LOGS")
	if v == "" {
		return slog.New(slog.DiscardHandler)
	}

	level := slog.LevelInfo
	switch v {
	case "2":
		level = slog.LevelDebug
	case "3":
		level = slog.Level(-8)
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}
