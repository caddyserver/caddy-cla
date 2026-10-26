// Package app serves contributor agreement pages and coordinates GitHub automation.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"caddy-cla/internal/config"
	"caddy-cla/internal/storage"
)

// Options selects the configuration and optional one-shot import or backup command.
type Options struct {
	// ConfigFile names the deployment settings file.
	ConfigFile string
	// ImportFile selects an upstream JSON import instead of serving HTTP.
	ImportFile string
	// BackupFile selects a new SQLite snapshot destination instead of serving HTTP.
	BackupFile string
}

// Run imports records, writes a backup or serves the application until ctx is canceled.
func Run(ctx context.Context, options Options) error {
	c, err := config.Load(options.ConfigFile)
	if err != nil {
		return err
	}
	body, err := os.ReadFile(c.AgreementFile)
	if err != nil {
		return err
	}
	s, err := storage.Open(c.Database)
	if err != nil {
		return err
	}
	defer s.Close()
	if err = s.Agreement(c.AgreementVersion, string(body), c.AgreementSource); err != nil {
		return err
	}
	if err = s.BootstrapRepositories(c.Repositories, c.RepositoryID, c.AgreementVersion, c.AgreementSource, storage.Policy{Users: c.ExemptUsers, PublicOrgs: c.ExemptPublicOrgs}); err != nil {
		return err
	}
	if options.ImportFile != "" {
		n, err := s.ImportFile(options.ImportFile, c.AgreementVersion, c.Repositories[0], c.AgreementSource, c.RepositoryID)
		if err != nil {
			return err
		}
		slog.Info("import completed", "records", n)
		return nil
	}
	if options.BackupFile != "" {
		if _, err = os.Stat(options.BackupFile); !os.IsNotExist(err) {
			return fmt.Errorf("backup destination must not exist")
		}
		f, err := os.OpenFile(options.BackupFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
		_, err = s.Exec("VACUUM INTO ?", options.BackupFile)
		return err
	}
	a := newApp(c, s)
	if c.AutomationEnabled {
		go a.work(ctx)
	}
	go a.maintenance(ctx)
	server := &http.Server{
		Addr:              c.Listen,
		Handler:           a.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      3 * time.Minute,
		IdleTimeout:       60 * time.Second,
	}
	done := make(chan error, 1)
	go func() {
		slog.Info("listening", "address", c.Listen, "base_url", c.BaseURL)
		done <- server.ListenAndServe()
	}()
	select {
	case err := <-done:
		if err != http.ErrServerClosed {
			return err
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
	return nil
}
