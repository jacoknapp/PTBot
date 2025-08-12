package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------- helpers ----------

func withEnv(k, v string, fn func()) {
	old, had := os.LookupEnv(k)
	_ = os.Setenv(k, v)
	defer func() {
		if had {
			_ = os.Setenv(k, old)
		} else {
			_ = os.Unsetenv(k)
		}
	}()
	fn()
}

// ---------- unit tests (pure helpers) ----------

func TestParseCSV(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"  ", nil},
		{"a", []string{"a"}},
		{"a,b,c", []string{"a", "b", "c"}},
		{" a ,  b ,c  ", []string{"a", "b", "c"}},
		{",,a,,", []string{"a"}},
	}
	for _, c := range cases {
		got := parseCSV(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("parseCSV(%q) len=%d want=%d", c.in, len(got), len(c.want))
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("parseCSV(%q)[%d]=%q want=%q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestEnvOrDefault(t *testing.T) {
	withEnv("X_TEST", "", func() {
		if v := envOrDefault("X_TEST", "def"); v != "def" {
			t.Fatalf("envOrDefault empty -> %q want def", v)
		}
	})
	withEnv("X_TEST", " value ", func() {
		if v := envOrDefault("X_TEST", "def"); v != "value" {
			t.Fatalf("envOrDefault set -> %q want value", v)
		}
	})
}

func TestParseDurDefault(t *testing.T) {
	d := parseDurDefault("5m", time.Minute)
	if d != 5*time.Minute {
		t.Fatalf("parseDurDefault 5m -> %v", d)
	}
	d = parseDurDefault("nope", 42*time.Second)
	if d != 42*time.Second {
		t.Fatalf("parseDurDefault invalid -> %v", d)
	}
}

// ---------- config bootstrap tests ----------

func TestWriteConfigFromEnvAndLoad(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.json")

	// Ensure no file exists; set some env to be captured

	withEnv("DISCORD_TOKEN", "env_discord", func() {
		withEnv("PTERO_BASE_URL", "https://panel.example.com", func() {
			withEnv("PTERO_CLIENT_TOKEN", "env_ptero", func() {
				// saner interval
				withEnv("HEALTH_CHECK_INTERVAL", "1m", func() {
					cfg, err := loadConfig(cfgPath)
					if err != nil {
						t.Fatalf("loadConfig: %v", err)
					}
					// File should exist now
					if _, err := os.Stat(cfgPath); err != nil {
						t.Fatalf("config file not created: %v", err)
					}
					if cfg.DiscordToken != "env_discord" {
						t.Fatalf("DiscordToken=%q", cfg.DiscordToken)
					}
					if cfg.PteroClientToken != "env_ptero" {
						t.Fatalf("PteroClientToken=%q", cfg.PteroClientToken)
					}
					if cfg.HealthCheckInterval != "1m" {
						t.Fatalf("HealthCheckInterval=%q", cfg.HealthCheckInterval)
					}

					// Ensure file actually contains what we expect (serialized struct)
					raw, _ := os.ReadFile(cfgPath)
					var onDisk Config
					if err := json.Unmarshal(raw, &onDisk); err != nil {
						t.Fatalf("unmarshal written config: %v", err)
					}
					if onDisk.DiscordToken == "" || onDisk.PteroClientToken == "" {
						t.Fatalf("written config missing tokens")
					}
				})
			})
		})
	})
}

func TestLoadConfigCreatesPlaceholders(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.json")

	// No env set -> should write placeholders
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig (placeholders): %v", err)
	}
	if cfg.DiscordToken == "" || cfg.PteroClientToken == "" {
		t.Fatalf("placeholders not set in memory")
	}
	raw, _ := os.ReadFile(cfgPath)
	s := string(raw)
	if !strings.Contains(s, "REPLACE_ME_DISCORD_TOKEN") || !strings.Contains(s, "REPLACE_ME_PTERO_TOKEN") {
		t.Fatalf("expected placeholder values written to file, got: %s", s)
	}
}

// ---------- HTTP-backed tests (stub Pterodactyl API) ----------

func TestListServersAndResolve(t *testing.T) {
	// stub Pterodactyl client API
	type page struct {
		Object string `json:"object"`
		Data   []struct {
			Object     string `json:"object"`
			Attributes struct {
				Identifier string `json:"identifier"`
				Name       string `json:"name"`
			} `json:"attributes"`
		} `json:"data"`
		Meta struct {
			Pagination struct {
				CurrentPage int `json:"current_page"`
				TotalPages  int `json:"total_pages"`
			} `json:"pagination"`
		} `json:"meta"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/client/servers/") && strings.HasSuffix(r.URL.Path, "/resources"):
			// minimal resources endpoint
			_ = json.NewEncoder(w).Encode(resourcesResp{
				Object: "stats",
				Attributes: struct {
					CurrentState string  `json:"current_state"`
					IsSuspended  bool    `json:"is_suspended"`
					Resources    struct {
						MemoryBytes     float64 `json:"memory_bytes"`
						CPUAbsolute     float64 `json:"cpu_absolute"`
						DiskBytes       float64 `json:"disk_bytes"`
						NetworkRxBytes  float64 `json:"network_rx_bytes"`
						NetworkTxBytes  float64 `json:"network_tx_bytes"`
					} `json:"resources"`
				}{
					CurrentState: "running",
					IsSuspended:  false,
					Resources: struct {
						MemoryBytes     float64 `json:"memory_bytes"`
						CPUAbsolute     float64 `json:"cpu_absolute"`
						DiskBytes       float64 `json:"disk_bytes"`
						NetworkRxBytes  float64 `json:"network_rx_bytes"`
						NetworkTxBytes  float64 `json:"network_tx_bytes"`
					}{
						MemoryBytes:    512 * 1024 * 1024,
						CPUAbsolute:    12.3,
						DiskBytes:      10 * 1024 * 1024 * 1024,
						NetworkRxBytes: 42 * 1024 * 1024,
						NetworkTxBytes: 7 * 1024 * 1024,
					},
				},
			})
			return

		case strings.HasPrefix(r.URL.Path, "/api/client"):
			// page=1 only, 3 servers
			resp := page{
				Object: "list",
				Data: []struct {
					Object     string "json:\"object\""
					Attributes struct {
						Identifier string "json:\"identifier\""
						Name       string "json:\"name\""
					} "json:\"attributes\""
				}{
					{Object: "server", Attributes: struct {
						Identifier string "json:\"identifier\""
						Name       string "json:\"name\""
					}{Identifier: "abc123", Name: "mc-lobby"}},
					{Object: "server", Attributes: struct {
						Identifier string "json:\"identifier\""
						Name       string "json:\"name\""
					}{Identifier: "def456", Name: "mc-prod"}},
					{Object: "server", Attributes: struct {
						Identifier string "json:\"identifier\""
						Name       string "json:\"name\""
					}{Identifier: "ghi789", Name: "valheim"}},
				},
			}
			resp.Meta.Pagination.CurrentPage = 1
			resp.Meta.Pagination.TotalPages = 1
			_ = json.NewEncoder(w).Encode(resp)
			return
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// inject minimal config
	config.Store(&Config{
		DiscordToken:     "x",
		PteroBaseURL:     srv.URL,
		PteroClientToken: "y",
	})

	// listServers
	got, err := listServers()
	if err != nil {
		t.Fatalf("listServers: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("listServers len=%d want 3", len(got))
	}

	// resolve exact
	id, err := resolveServerIDByName("valheim")
	if err != nil || id != "ghi789" {
		t.Fatalf("resolve exact -> (%s,%v)", id, err)
	}
	// resolve prefix
	id, err = resolveServerIDByName("mc-")
	if err == nil {
		t.Fatalf("expected ambiguous error for prefix 'mc-', got id=%s", id)
	}
	// resolve unique prefix
	id, err = resolveServerIDByName("val")
	if err != nil || id != "ghi789" {
		t.Fatalf("resolve prefix -> (%s,%v)", id, err)
	}

	// getResources
	stats, err := getResources("abc123")
	if err != nil {
		t.Fatalf("getResources: %v", err)
	}
	if stats.Attributes.CurrentState != "running" || stats.Attributes.Resources.CPUAbsolute <= 0 {
		t.Fatalf("unexpected resources: %+v", stats.Attributes)
	}
}
