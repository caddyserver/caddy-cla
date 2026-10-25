package app

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

// webImport accepts bounded raw JSON or CSV uploads after repository-specific authorization.
func (a *App) webImport(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(2 << 20); err != nil {
		http.Error(w, "Upload is invalid or exceeds the 8 MiB request limit", 400)
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	if _, ok := a.csrf(w, r); !ok {
		return
	}
	if _, ok := a.authorized(w, r); !ok {
		return
	}
	cfg, err := a.repository(r)
	if err != nil {
		http.Error(w, "Repository not found", 404)
		return
	}
	version := r.FormValue("version")
	if version == "" {
		version = cfg.Version
	}
	var source string
	if err = a.s.QueryRow("SELECT source FROM agreements WHERE version=?", version).Scan(&source); err != nil {
		http.Error(w, "Import requires an existing agreement version", 400)
		return
	}
	file, header, err := r.FormFile("signatures")
	if err != nil {
		http.Error(w, "Choose a JSON or CSV signature export", 400)
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (6<<20)+1))
	if err != nil || len(data) > 6<<20 {
		http.Error(w, "Signature file exceeds 6 MiB", 400)
		return
	}
	if strings.EqualFold(filepath.Ext(header.Filename), ".csv") {
		data, err = csvSignatures(data)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
	}
	count, err := a.s.ImportJSON(data, version, cfg.Name, source, cfg.GitHubID)
	if err != nil {
		http.Error(w, "Import rejected; no records changed: "+err.Error(), 400)
		return
	}
	http.Redirect(w, r, a.repoURL("/admin", cfg.Name)+fmt.Sprintf("&imported=%d", count), 303)
}

// csvSignatures retains the original CSV cells while mapping recognized upstream export columns.
// Username-only rows become unresolved historical identities; they never grant automatic approval.
func csvSignatures(data []byte) ([]byte, error) {
	reader := csv.NewReader(bytes.NewReader(data))
	line := strings.SplitN(string(data), "\n", 2)[0]
	if strings.Count(line, ";") > strings.Count(line, ",") {
		reader.Comma = ';'
	}
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("invalid CSV: %w", err)
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("CSV contains no signature records")
	}
	records := []map[string]any{}
	for _, row := range rows[1:] {
		m := map[string]any{}
		raw := map[string]string{}
		for i, value := range row {
			header := strings.TrimSpace(strings.TrimPrefix(rows[0][i], "\ufeff"))
			raw[header] = value
			switch strings.ToLower(header) {
			case "user name", "username", "login":
				m["user"] = value
			case "github id", "userid", "user id":
				if value != "" {
					m["userId"] = value
				}
			case "repository owner":
				m["owner"] = value
			case "repository name":
				m["repo"] = value
			case "gist url":
				m["gist_url"] = value
			case "gist version", "agreement version":
				m["gist_version"] = value
			case "signed at", "signed at (utc)":
				m["created_at"] = value
			case "ends at", "end at", "expires at":
				if value != "" {
					m["end_at"] = value
				}
			case "revoked at":
				if value != "" {
					m["revoked_at"] = value
				}
			}
		}
		if date, ok := m["created_at"].(string); ok {
			for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05 -0700 MST", "2006-01-02 15:04:05"} {
				if parsed, err := time.Parse(layout, date); err == nil {
					m["created_at"] = parsed.UTC().Format(time.RFC3339Nano)
					break
				}
			}
		}
		m["original_csv"] = raw
		records = append(records, m)
	}
	return json.Marshal(records)
}
