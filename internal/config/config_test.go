package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestHostingPaths verifies root and nested prefixes produce consistent public URLs and routes.
func TestHostingPaths(t *testing.T) {
	for _, test := range []struct{ prefix, want string }{
		{"/", ""}, {"", ""}, {"/cla", "/cla"}, {"/agreements/cla/", "/agreements/cla"},
	} {
		t.Run(test.prefix, func(t *testing.T) {
			settings := map[string]any{
				"base_url":          "https://example.com/",
				"base_path":         test.prefix,
				"agreement_file":    "agreement.md",
				"agreement_version": "v1",
				"repositories":      []string{"owner/repo"},
			}
			data, err := json.Marshal(settings)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "config.json")
			if err = os.WriteFile(file, data, 0600); err != nil {
				t.Fatal(err)
			}
			c, err := Load(file)
			if err != nil {
				t.Fatal(err)
			}
			if c.BasePath != test.want || c.BaseURL != "https://example.com" || c.PublicURL() != "https://example.com"+test.want {
				t.Fatalf("unexpected canonical configuration: %+v", c)
			}
			if c.Path("/auth/github/callback") != test.want+"/auth/github/callback" {
				t.Fatal("incorrect callback path")
			}
		})
	}
}

// TestInvalidHostingPaths rejects path traversal, malformed prefixes and paths hidden in the origin.
func TestInvalidHostingPaths(t *testing.T) {
	for _, prefix := range []string{"cla", "/../cla", "/cla/./test", "/cla?x=1", "/cla#fragment", "/cla%2Ftest", "/cla\\test", "/two words", "//cla"} {
		data, _ := json.Marshal(map[string]any{
			"base_url": "https://example.com", "base_path": prefix,
			"agreement_file": "agreement.md", "agreement_version": "v1",
			"repositories": []string{"owner/repo"},
		})
		file := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(file); err == nil {
			t.Errorf("accepted invalid prefix %q", prefix)
		}
	}
}
