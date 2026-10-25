// Command caddy-cla serves Caddy contributor agreements and manages their records.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"caddy-cla/internal/app"
)

// main parses command flags and cancels the service on an operating-system signal.
func main() {
	var options app.Options
	flag.StringVar(&options.ConfigFile, "config", "config.json", "configuration file")
	flag.StringVar(&options.ImportFile, "import", "", "import raw CLA Assistant JSON, then exit")
	flag.StringVar(&options.BackupFile, "backup", "", "write consistent SQLite backup to a new path, then exit")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx, options); err != nil {
		slog.Error("caddy-cla", "error", err)
		os.Exit(1)
	}
}
