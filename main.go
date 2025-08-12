package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"crypto/tls"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
)

type Config struct {
	DiscordToken        string   `json:"discord_token"`
	AllowedGuildIDs     []string `json:"allowed_guild_ids"`
	AllowedRoleIDs      []string `json:"allowed_role_ids"`
	AllowedUserIDs      []string `json:"allowed_user_ids"`
	PteroBaseURL        string   `json:"ptero_base_url"`
	PteroClientToken    string   `json:"ptero_client_token"`
	AlertChannelID      string   `json:"alert_channel_id"`
	HealthCheckInterval string   `json:"health_check_interval"`
}

var (
	cfgPath    = flag.String("config", "/data/config.json", "path to config.json")
	insecure   = flag.Bool("insecure", false, "allow untrusted TLS certificates for ptpanel endpoint")
	config     atomic.Value // *Config
	httpClient = &http.Client{Timeout: 15 * time.Second}

	bgCtx    context.Context
	bgCancel context.CancelFunc

	sess        *discordgo.Session
	appCommands []*discordgo.ApplicationCommand
)

func main() {

	flag.Parse()

	// Ensure /data directory exists and set permissions (no chown, safe for non-root)
	dataDir := "/data"
	if err := os.MkdirAll(dataDir, 0770); err != nil {
		log.Fatalf("failed to create %s: %v", dataDir, err)
	}
	if err := os.Chmod(dataDir, 0770); err != nil {
		log.Printf("warning: failed to chmod %s: %v", dataDir, err)
	}

	// Check environment variable for insecure mode
	envInsecure := os.Getenv("PTBOT_INSECURE")
	useInsecure := *insecure
	if envInsecure != "" {
		useInsecure = strings.ToLower(envInsecure) == "true" || envInsecure == "1"
	}

	// Setup httpClient with optional insecure TLS
	if useInsecure {
		httpClient = &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		log.Println("⚠️ INSECURE mode: skipping TLS certificate verification for ptpanel endpoint")
	} else {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}
	config.Store(cfg)

	bgCtx, bgCancel = context.WithCancel(context.Background())
	defer bgCancel()

	s, err := discordgo.New("Bot " + cfg.DiscordToken)
	if err != nil {
		log.Fatalf("discord: %v", err)
	}
	sess = s
	sess.Identify.Intents = discordgo.IntentsGuilds | discordgo.IntentsGuildMembers
	sess.AddHandler(onInteractionCreate)
	sess.AddHandler(onAutocomplete)

	if err := sess.Open(); err != nil {
		log.Fatalf("discord open: %v", err)
	}
	defer sess.Close()
	log.Printf("✅ Logged in as %s", sess.State.User.ID)

	if err := registerCommands(); err != nil {
		log.Fatalf("register commands: %v", err)
	}

	go healthLoop()

	// Signals: SIGHUP reload, INT/TERM exit
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	for {
		switch <-sigc {
		case syscall.SIGHUP:
			reload()
		default:
			log.Println("shutdown...")
			return
		}
	}
}

// ---------- Discord handlers ----------

func onInteractionCreate(s *discordgo.Session, i *discordgo.InteractionCreate) {
	if i.Type != discordgo.InteractionApplicationCommand {
		return
	}
	if i.ApplicationCommandData().Name != "pt" {
		return
	}
	ok, why := isAllowed(i)
	if !ok {
		respondEphemeral(s, i, fmt.Sprintf("🚫 Not allowed: %s", why))
		return
	}

	switch i.ApplicationCommandData().Options[0].Name {
	case "list":
		doList(s, i)
	case "status":
		doStatus(s, i)
	case "start":
		doPower(s, i, "start")
	case "stop":
		doPower(s, i, "stop")
	case "restart":
		doPower(s, i, "restart")
	case "send":
		doSend(s, i)
	}
}

func onAutocomplete(s *discordgo.Session, i *discordgo.InteractionCreate) {
	if i.Type != discordgo.InteractionApplicationCommandAutocomplete {
		return
	}
	if i.ApplicationCommandData().Name != "pt" {
		return
	}

	// find partial for the "name" option
	var partial string
	opts := i.ApplicationCommandData().Options
	if len(opts) > 0 && len(opts[0].Options) > 0 {
		for _, opt := range opts[0].Options {
			if opt.Focused && opt.Name == "name" {
				if v, ok := opt.Value.(string); ok {
					partial = v
				}
			}
		}
	}

	servers, err := listServers()
	if err != nil {
		servers = nil
	}
	lc := strings.ToLower(strings.TrimSpace(partial))
	choices := make([]*discordgo.ApplicationCommandOptionChoice, 0, 25)

	addMatches := func(match func(string) bool) {
		for _, sv := range servers {
			name := sv.Name
			if match(strings.ToLower(name)) {
				choices = append(choices, &discordgo.ApplicationCommandOptionChoice{
					Name:  name,
					Value: name,
				})
				if len(choices) >= 25 {
					return
				}
			}
		}
	}

	if lc == "" {
		sort.Slice(servers, func(i, j int) bool { return servers[i].Name < servers[j].Name })
		for _, sv := range servers {
			choices = append(choices, &discordgo.ApplicationCommandOptionChoice{Name: sv.Name, Value: sv.Name})
			if len(choices) >= 25 {
				break
			}
		}
	} else {
		addMatches(func(n string) bool { return n == lc })
		if len(choices) < 25 {
			addMatches(func(n string) bool { return strings.HasPrefix(n, lc) })
		}
		if len(choices) < 25 {
			addMatches(func(n string) bool { return strings.Contains(n, lc) })
		}
	}

	_ = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionApplicationCommandAutocompleteResult,
		Data: &discordgo.InteractionResponseData{Choices: choices},
	})
}

func isAllowed(i *discordgo.InteractionCreate) (bool, string) {
	cfg := getCfg()
	if len(cfg.AllowedGuildIDs) > 0 {
		found := false
		for _, g := range cfg.AllowedGuildIDs {
			if g == i.GuildID {
				found = true
				break
			}
		}
		if !found {
			return false, "guild not in allowlist"
		}
	}
	uid := i.Member.User.ID
	for _, u := range cfg.AllowedUserIDs {
		if u == uid {
			return true, "allowed user"
		}
	}
	if len(cfg.AllowedRoleIDs) == 0 {
		return true, "no role restriction"
	}
	roleSet := map[string]struct{}{}
	for _, r := range i.Member.Roles {
		roleSet[r] = struct{}{}
	}
	for _, allowed := range cfg.AllowedRoleIDs {
		if _, ok := roleSet[allowed]; ok {
			return true, "has allowed role"
		}
	}
	return false, "missing required role"
}

// ---------- Slash commands ----------

func registerCommands() error {
	cmd := &discordgo.ApplicationCommand{
		Name:        "pt",
		Description: "Pterodactyl controls",
		Options: []*discordgo.ApplicationCommandOption{
			{Type: discordgo.ApplicationCommandOptionSubCommand, Name: "list", Description: "List visible servers"},
			{
				Type:        discordgo.ApplicationCommandOptionSubCommand,
				Name:        "status",
				Description: "Get server status by name",
				Options: []*discordgo.ApplicationCommandOption{
					{Name: "name", Description: "Server name (exact/prefix)", Type: discordgo.ApplicationCommandOptionString, Required: true, Autocomplete: true},
				},
			},
			{
				Type:        discordgo.ApplicationCommandOptionSubCommand,
				Name:        "start",
				Description: "Start a server by name",
				Options: []*discordgo.ApplicationCommandOption{
					{Name: "name", Description: "Server name (exact/prefix)", Type: discordgo.ApplicationCommandOptionString, Required: true, Autocomplete: true},
				},
			},
			{
				Type:        discordgo.ApplicationCommandOptionSubCommand,
				Name:        "stop",
				Description: "Stop a server by name",
				Options: []*discordgo.ApplicationCommandOption{
					{Name: "name", Description: "Server name (exact/prefix)", Type: discordgo.ApplicationCommandOptionString, Required: true, Autocomplete: true},
				},
			},
			{
				Type:        discordgo.ApplicationCommandOptionSubCommand,
				Name:        "restart",
				Description: "Restart a server by name",
				Options: []*discordgo.ApplicationCommandOption{
					{Name: "name", Description: "Server name (exact/prefix)", Type: discordgo.ApplicationCommandOptionString, Required: true, Autocomplete: true},
				},
			},
			{
				Type:        discordgo.ApplicationCommandOptionSubCommand,
				Name:        "send",
				Description: "Send a console command",
				Options: []*discordgo.ApplicationCommandOption{
					{Name: "name", Description: "Server name (exact/prefix)", Type: discordgo.ApplicationCommandOptionString, Required: true, Autocomplete: true},
					{Name: "command", Description: "Console command", Type: discordgo.ApplicationCommandOptionString, Required: true},
				},
			},
		},
	}
	ac, err := sess.ApplicationCommandCreate(sess.State.User.ID, "", cmd)
	if err != nil {
		return err
	}
	appCommands = []*discordgo.ApplicationCommand{ac}
	log.Printf("Slash command /pt registered.")
	return nil
}

func doList(s *discordgo.Session, i *discordgo.InteractionCreate) {
	respondThinking(s, i)
	servers, err := listServers()
	if err != nil {
		editFollowup(s, i, fmt.Sprintf("❌ list error: %v", err))
		return
	}
	if len(servers) == 0 {
		editFollowup(s, i, "No servers visible for this token.")
		return
	}
	names := make([]string, 0, len(servers))
	for _, sv := range servers {
		names = append(names, sv.Name)
	}
	sort.Strings(names)
	editFollowup(s, i, "**Servers**\n• "+strings.Join(names, "\n• "))
}

func doStatus(s *discordgo.Session, i *discordgo.InteractionCreate) {
	name := optionString(i, "name")
	id, err := resolveServerIDByName(name)
	if err != nil {
		respondEphemeral(s, i, "❌ "+err.Error())
		return
	}
	respondThinking(s, i)
	st, err := getResources(id)
	if err != nil {
		editFollowup(s, i, fmt.Sprintf("❌ status error: %v", err))
		return
	}
	msg := fmt.Sprintf(
		"**%s** (`%s`)\nState: **%s**%s\nCPU: %.1f%%  Mem: %.1f MiB  Disk: %.1f GiB\nNet: rx %.1f MiB / tx %.1f MiB",
		name, id, st.Attributes.CurrentState, ternary(st.Attributes.IsSuspended, " (suspended)", ""),
		st.Attributes.Resources.CPUAbsolute,
		float64(st.Attributes.Resources.MemoryBytes)/(1024*1024),
		float64(st.Attributes.Resources.DiskBytes)/(1024*1024*1024),
		float64(st.Attributes.Resources.NetworkRxBytes)/(1024*1024),
		float64(st.Attributes.Resources.NetworkTxBytes)/(1024*1024),
	)
	editFollowup(s, i, msg)
}

func doPower(s *discordgo.Session, i *discordgo.InteractionCreate, signal string) {
	name := optionString(i, "name")
	id, err := resolveServerIDByName(name)
	if err != nil {
		respondEphemeral(s, i, "❌ "+err.Error())
		return
	}
	respondThinking(s, i)
	if err := postPower(id, signal); err != nil {
		editFollowup(s, i, fmt.Sprintf("❌ %s failed: %v", signal, err))
		return
	}
	editFollowup(s, i, fmt.Sprintf("✅ issued `%s` to **%s**", signal, name))
}

func doSend(s *discordgo.Session, i *discordgo.InteractionCreate) {
	name := optionString(i, "name")
	cmd := optionString(i, "command")
	id, err := resolveServerIDByName(name)
	if err != nil {
		respondEphemeral(s, i, "❌ "+err.Error())
		return
	}
	respondThinking(s, i)
	if err := postCommand(id, cmd); err != nil {
		editFollowup(s, i, fmt.Sprintf("❌ send failed: %v", err))
		return
	}
	editFollowup(s, i, fmt.Sprintf("📤 sent to **%s**: `%s`", name, cmd))
}

func optionString(i *discordgo.InteractionCreate, name string) string {
	for _, opt := range i.ApplicationCommandData().Options[0].Options {
		if opt.Name == name {
			if v, ok := opt.Value.(string); ok {
				return v
			}
		}
	}
	return ""
}

func respondEphemeral(s *discordgo.Session, i *discordgo.InteractionCreate, msg string) {
	_ = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Content: msg, Flags: discordgo.MessageFlagsEphemeral},
	})
}
func respondThinking(s *discordgo.Session, i *discordgo.InteractionCreate) {
	_ = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Flags: discordgo.MessageFlagsEphemeral},
	})
}
func editFollowup(s *discordgo.Session, i *discordgo.InteractionCreate, msg string) {
	_, _ = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{Content: &msg})
}

func reload() {
	newCfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Printf("reload failed: %v", err)
		return
	}
	config.Store(newCfg)
	log.Printf("🔁 reloaded config")
}
func getCfg() *Config { return config.Load().(*Config) }

// ---------- Pterodactyl Client API ----------

type serverListResp struct {
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

type resourcesResp struct {
	Object     string `json:"object"`
	Attributes struct {
		CurrentState string `json:"current_state"`
		IsSuspended  bool   `json:"is_suspended"`
		Resources    struct {
			MemoryBytes     float64 `json:"memory_bytes"`
			CPUAbsolute     float64 `json:"cpu_absolute"`
			DiskBytes       float64 `json:"disk_bytes"`
			NetworkRxBytes  float64 `json:"network_rx_bytes"`
			NetworkTxBytes  float64 `json:"network_tx_bytes"`
		} `json:"resources"`
	} `json:"attributes"`
}

type serverInfo struct {
	ID   string
	Name string
}

func listServers() ([]serverInfo, error) {
	cfg := getCfg()
	page := 1
	var out []serverInfo
	for {
		url := strings.TrimRight(cfg.PteroBaseURL, "/") + fmt.Sprintf("/api/client?page=%d&per_page=100", page)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+cfg.PteroClientToken)
		req.Header.Set("Accept", "application/json")
		res, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		if res.StatusCode >= 300 {
			b, _ := io.ReadAll(res.Body)
			return nil, fmt.Errorf("GET %s -> %d: %s", url, res.StatusCode, string(b))
		}
		var r serverListResp
		if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
			return nil, err
		}
		for _, d := range r.Data {
			out = append(out, serverInfo{ID: d.Attributes.Identifier, Name: d.Attributes.Name})
		}
		if r.Meta.Pagination.CurrentPage >= r.Meta.Pagination.TotalPages {
			break
		}
		page++
	}
	return out, nil
}

func resolveServerIDByName(input string) (string, error) {
	if strings.TrimSpace(input) == "" {
		return "", errors.New("server name is required")
	}
	servers, err := listServers()
	if err != nil {
		return "", err
	}
	lc := strings.ToLower(strings.TrimSpace(input))
	var matches []serverInfo
	for _, s := range servers {
		name := strings.ToLower(s.Name)
		if name == lc || strings.HasPrefix(name, lc) {
			matches = append(matches, s)
		}
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("no server matched name '%s' (use /pt list)", input)
	}
	if len(matches) > 1 {
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, m.Name)
		}
		return "", fmt.Errorf("ambiguous: matched %d servers: %s", len(matches), strings.Join(names, ", "))
	}
	return matches[0].ID, nil
}

func getResources(id string) (*resourcesResp, error) {
	url := strings.TrimRight(getCfg().PteroBaseURL, "/") + "/api/client/servers/" + id + "/resources"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+getCfg().PteroClientToken)
	req.Header.Set("Accept", "application/json")
	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		b, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("GET %s -> %d: %s", url, res.StatusCode, string(b))
	}
	var out resourcesResp
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func postPower(id, signal string) error {
	url := strings.TrimRight(getCfg().PteroBaseURL, "/") + "/api/client/servers/" + id + "/power"
	body := map[string]string{"signal": signal}
	j, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(j))
	req.Header.Set("Authorization", "Bearer "+getCfg().PteroClientToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("POST %s -> %d: %s", url, res.StatusCode, string(b))
	}
	return nil
}

func postCommand(id, cmd string) error {
	url := strings.TrimRight(getCfg().PteroBaseURL, "/") + "/api/client/servers/" + id + "/command"
	body := map[string]string{"command": cmd}
	j, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(j))
	req.Header.Set("Authorization", "Bearer "+getCfg().PteroClientToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("POST %s -> %d: %s", url, res.StatusCode, string(b))
	}
	return nil
}

// ---------- Maintenance ----------

var onceAlert sync.Once

func healthLoop() {
	cfg := getCfg()
	interval := parseDurDefault(cfg.HealthCheckInterval, 2*time.Minute)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-bgCtx.Done():
			return
		case <-t.C:
			if err := checkPanelHealth(); err != nil {
				log.Printf("panel: %v", err)
				alert(err.Error())
			} else {
				onceAlert = sync.Once{}
			}
		}
	}
}

func checkPanelHealth() error {
	cfg := getCfg()
	url := strings.TrimRight(cfg.PteroBaseURL, "/") + "/api/client/account"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+cfg.PteroClientToken)
	req.Header.Set("Accept", "application/json")
	res, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("panel unreachable: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("panel unhealthy %d: %s", res.StatusCode, string(b))
	}
	return nil
}

func alert(msg string) {
	cfg := getCfg()
	if cfg.AlertChannelID == "" || sess == nil {
		return
	}
	onceAlert.Do(func() { _, _ = sess.ChannelMessageSend(cfg.AlertChannelID, "⚠️ Pterodactyl health check failed: "+msg) })
}

// ---------- utils ----------

func loadConfig(path string) (*Config, error) {
	// If missing, create from ENV (or placeholders), then read it back
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := writeConfigFromEnv(path); err != nil {
			return nil, fmt.Errorf("failed to write config: %w", err)
		}
		log.Printf("✨ Created config at %s from environment (or defaults)", path)
	} else if err != nil {
		return nil, fmt.Errorf("checking config: %w", err)
	}

	// Load file
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	// Env overrides (ENV > file)
	if v := os.Getenv("DISCORD_TOKEN"); v != "" { c.DiscordToken = v }
	if v := os.Getenv("PTERO_BASE_URL"); v != "" { c.PteroBaseURL = v }
	if v := os.Getenv("PTERO_CLIENT_TOKEN"); v != "" { c.PteroClientToken = v }
	if v := os.Getenv("ALERT_CHANNEL_ID"); v != "" { c.AlertChannelID = v }
	if v := os.Getenv("HEALTH_CHECK_INTERVAL"); v != "" { c.HealthCheckInterval = v }

	// CSV allowlists via env (override arrays if provided)
	if v := os.Getenv("ALLOWED_GUILD_IDS"); v != "" { c.AllowedGuildIDs = parseCSV(v) }
	if v := os.Getenv("ALLOWED_ROLE_IDS"); v != "" { c.AllowedRoleIDs = parseCSV(v) }
	if v := os.Getenv("ALLOWED_USER_IDS"); v != "" { c.AllowedUserIDs = parseCSV(v) }

	// Warn if still placeholders
	if c.DiscordToken == "" || c.PteroBaseURL == "" || c.PteroClientToken == "" ||
		c.DiscordToken == "REPLACE_ME_DISCORD_TOKEN" || c.PteroClientToken == "REPLACE_ME_PTERO_TOKEN" {
		log.Println("⚠️ Warning: required fields may be placeholders; bot will not function until updated.")
	}
	return &c, nil
}

func writeConfigFromEnv(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	template := Config{
		DiscordToken:        envOrDefault("DISCORD_TOKEN", "REPLACE_ME_DISCORD_TOKEN"),
		AllowedGuildIDs:     parseCSV(os.Getenv("ALLOWED_GUILD_IDS")),
		AllowedRoleIDs:      parseCSV(os.Getenv("ALLOWED_ROLE_IDS")),
		AllowedUserIDs:      parseCSV(os.Getenv("ALLOWED_USER_IDS")),
		PteroBaseURL:        envOrDefault("PTERO_BASE_URL", "https://panel.example.com"),
		PteroClientToken:    envOrDefault("PTERO_CLIENT_TOKEN", "REPLACE_ME_PTERO_TOKEN"),
		AlertChannelID:      os.Getenv("ALERT_CHANNEL_ID"),
		HealthCheckInterval: envOrDefault("HEALTH_CHECK_INTERVAL", "2m"),
	}

	b, _ := json.MarshalIndent(template, "", "  ")
	return os.WriteFile(path, b, 0o640)
}

func envOrDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func parseDurDefault(s string, d time.Duration) time.Duration {
	if s == "" {
		return d
	}
	if v, err := time.ParseDuration(s); err == nil {
		return v
	}
	return d
}

func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func ternary[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}
