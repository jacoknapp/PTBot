// Package main implements PTBot, a Discord bot that controls Pterodactyl servers
// via slash commands. It supports per-user API tokens (encrypted at rest),
// autocomplete, health checks, and role/user/guild allowlists.
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"encoding/base64"

	"github.com/bwmarrin/discordgo"
	"golang.org/x/crypto/scrypt"
)

// Config contains runtime settings loaded from /data/config.json and
// optionally overridden by environment variables.
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

	// user-specific Pterodactyl client tokens (keyed by Discord user ID)
	userTokens   map[string]string
	userTokensMu sync.RWMutex
)

// main is the PTBot entrypoint; it loads configuration, initializes Discord,
// prepares encryption keys, registers commands, and starts health checks.
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

	// Initialize the last-known health as good to avoid a false recovery message on first success
	lastHealth.Store(true)

	// Ensure token encryption key is initialized early (safe generation paths only)
	if err := initTokenEncryptionKey(); err != nil {
		log.Printf("warning: token key init: %v", err)
	}

	// Load any existing user token mappings
	if err := loadUserTokens(); err != nil {
		log.Printf("warning: failed to load user tokens: %v", err)
	}

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

// onInteractionCreate handles the /pt slash command invocations and routes
// to the appropriate subcommand implementation after allowlist checks.
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
	case "backup":
		doBackup(s, i)
	case "send":
		doSend(s, i)
	case "key":
		doSetKey(s, i)
	}
}

// onAutocomplete serves dynamic choices for the "name" option by querying
// the Pterodactyl API using the requesting user's effective token.
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

	// Use the requesting user's token for autocomplete suggestions; if none is available, return no choices
	effTok, _ := tokenForUserOrError(i.Member.User.ID)
	servers, err := listServers(effTok)
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

// isAllowed enforces guild/role/user allowlists and returns a boolean along
// with a short reason string for audit and user feedback.
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

// registerCommands registers the single top-level /pt command with all
// supported subcommands and options.
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
				Name:        "backup",
				Description: "Create a backup for a server",
				Options: []*discordgo.ApplicationCommandOption{
					{Name: "name", Description: "Server name (exact/prefix)", Type: discordgo.ApplicationCommandOptionString, Required: true, Autocomplete: true},
					{Name: "backup_name", Description: "Optional backup name/description", Type: discordgo.ApplicationCommandOptionString, Required: false},
					{Name: "ignored", Description: "Optional ignored patterns (one per line)", Type: discordgo.ApplicationCommandOptionString, Required: false},
					{Name: "lock", Description: "Lock the backup from deletion", Type: discordgo.ApplicationCommandOptionBoolean, Required: false},
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
			{
				Type:        discordgo.ApplicationCommandOptionSubCommand,
				Name:        "key",
				Description: "Set or clear your personal Pterodactyl API key",
				Options: []*discordgo.ApplicationCommandOption{
					{Name: "value", Description: "Your Pterodactyl client API token (send 'clear' to remove)", Type: discordgo.ApplicationCommandOptionString, Required: true},
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

// doList lists visible servers for the user's effective token.
func doList(s *discordgo.Session, i *discordgo.InteractionCreate) {
	tok, err := tokenForUserOrError(i.Member.User.ID)
	if err != nil {
		respondEphemeral(s, i, "❌ "+err.Error())
		return
	}
	respondThinking(s, i)
	servers, err := listServers(tok)
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
	// Pretty embed list
	embed := &discordgo.MessageEmbed{
		Title:       fmt.Sprintf("Servers (%d)", len(names)),
		Description: "• " + strings.Join(names, "\n• "),
		Color:       0x5865F2, // blurple
		Timestamp:   time.Now().Format(time.RFC3339),
	}
	editFollowupEmbed(s, i, embed)
}

// doStatus shows live resource stats for a server, resolving by exact or
// unique-prefix match under the user's effective token.
func doStatus(s *discordgo.Session, i *discordgo.InteractionCreate) {
	name := optionString(i, "name")
	tok, err := tokenForUserOrError(i.Member.User.ID)
	if err != nil {
		respondEphemeral(s, i, "❌ "+err.Error())
		return
	}
	id, err := resolveServerIDByName(name, tok)
	if err != nil {
		respondEphemeral(s, i, "❌ "+err.Error())
		return
	}
	respondThinking(s, i)
	st, err := getResources(id, tok)
	if err != nil {
		editFollowup(s, i, fmt.Sprintf("❌ status error: %v", err))
		return
	}
	// Pretty embed status
	state := st.Attributes.CurrentState
	suspended := st.Attributes.IsSuspended
	memMiB := float64(st.Attributes.Resources.MemoryBytes) / (1024 * 1024)
	diskGiB := float64(st.Attributes.Resources.DiskBytes) / (1024 * 1024 * 1024)
	rxMiB := float64(st.Attributes.Resources.NetworkRxBytes) / (1024 * 1024)
	txMiB := float64(st.Attributes.Resources.NetworkTxBytes) / (1024 * 1024)
	fields := []*discordgo.MessageEmbedField{
		{Name: "State", Value: fmt.Sprintf("%s %s", stateEmoji(state, suspended), boldState(state, suspended)), Inline: true},
		{Name: "CPU", Value: fmt.Sprintf("%.1f%%", st.Attributes.Resources.CPUAbsolute), Inline: true},
		{Name: "Memory", Value: fmt.Sprintf("%.1f MiB", memMiB), Inline: true},
		{Name: "Disk", Value: fmt.Sprintf("%.1f GiB", diskGiB), Inline: true},
		{Name: "Network", Value: fmt.Sprintf("⬇️ %.1f MiB\n⬆️ %.1f MiB", rxMiB, txMiB), Inline: true},
	}
	embed := &discordgo.MessageEmbed{
		Title:       fmt.Sprintf("%s", name),
		Description: fmt.Sprintf("`%s`", id),
		Fields:      fields,
		Color:       stateColor(state, suspended),
		Timestamp:   time.Now().Format(time.RFC3339),
	}
	editFollowupEmbed(s, i, embed)
}

// doPower sends a power action (start/stop/restart) to a server on behalf of
// the requesting user (using their effective token).
func doPower(s *discordgo.Session, i *discordgo.InteractionCreate, signal string) {
	name := optionString(i, "name")
	tok, err := tokenForUserOrError(i.Member.User.ID)
	if err != nil {
		respondEphemeral(s, i, "❌ "+err.Error())
		return
	}
	id, err := resolveServerIDByName(name, tok)
	if err != nil {
		respondEphemeral(s, i, "❌ "+err.Error())
		return
	}
	respondThinking(s, i)
	if err := postPower(id, signal, tok); err != nil {
		editFollowup(s, i, fmt.Sprintf("❌ %s failed: %v", signal, err))
		return
	}
	// Pretty embed confirmation
	embed := &discordgo.MessageEmbed{
		Title:       "Action issued",
		Description: fmt.Sprintf("`%s` → **%s**", signal, name),
		Color:       0x57F287, // green
		Timestamp:   time.Now().Format(time.RFC3339),
		Fields: []*discordgo.MessageEmbedField{
			{Name: "Server ID", Value: fmt.Sprintf("`%s`", id), Inline: true},
			{Name: "Action", Value: signal, Inline: true},
		},
	}
	editFollowupEmbed(s, i, embed)

	// Announce publicly in the channel who requested the action
	// derive a friendly display name (nick or username)
	requester := userDisplayName(i.Member)
	publicEmbed := &discordgo.MessageEmbed{
		Title:     "Server action",
		Color:     0x5865F2,
		Timestamp: time.Now().Format(time.RFC3339),
		Fields: []*discordgo.MessageEmbedField{
			{Name: "Server", Value: fmt.Sprintf("**%s**\n`%s`", name, id), Inline: true},
			{Name: "Action", Value: signal, Inline: true},
			{Name: "Requested by", Value: requester, Inline: true},
		},
	}
	content := fmt.Sprintf("🛠️ %s is running the action %s on %s", requester, signal, name)
	_, _ = s.ChannelMessageSendComplex(i.ChannelID, &discordgo.MessageSend{Content: content, Embeds: []*discordgo.MessageEmbed{publicEmbed}})
}

// userDisplayName returns the best display name for a member (nick > username > id)
func userDisplayName(m *discordgo.Member) string {
	if m == nil || m.User == nil {
		return "unknown"
	}
	if strings.TrimSpace(m.Nick) != "" {
		return m.Nick
	}
	if strings.TrimSpace(m.User.Username) != "" {
		return m.User.Username
	}
	return m.User.ID
}

// doSend sends a console command to the specified server using the user's
// effective token.
func doSend(s *discordgo.Session, i *discordgo.InteractionCreate) {
	name := optionString(i, "name")
	cmd := optionString(i, "command")
	tok, err := tokenForUserOrError(i.Member.User.ID)
	if err != nil {
		respondEphemeral(s, i, "❌ "+err.Error())
		return
	}
	id, err := resolveServerIDByName(name, tok)
	if err != nil {
		respondEphemeral(s, i, "❌ "+err.Error())
		return
	}
	respondThinking(s, i)
	if err := postCommand(id, cmd, tok); err != nil {
		editFollowup(s, i, fmt.Sprintf("❌ send failed: %v", err))
		return
	}
	embed := &discordgo.MessageEmbed{
		Title:     "Command sent",
		Color:     0x5865F2,
		Timestamp: time.Now().Format(time.RFC3339),
		Fields: []*discordgo.MessageEmbedField{
			{Name: "Server", Value: fmt.Sprintf("**%s**\n`%s`", name, id), Inline: true},
			{Name: "Command", Value: fmt.Sprintf("`%s`", cmd), Inline: true},
		},
	}
	editFollowupEmbed(s, i, embed)
}

// doBackup triggers a Pterodactyl backup for the specified server.
// Uses the caller's effective token. Accepts optional label.
func doBackup(s *discordgo.Session, i *discordgo.InteractionCreate) {
	name := optionString(i, "name")
	backupName := optionString(i, "backup_name")
	ignored := optionString(i, "ignored")
	lock := optionBool(i, "lock")
	tok, err := tokenForUserOrError(i.Member.User.ID)
	if err != nil {
		respondEphemeral(s, i, "❌ "+err.Error())
		return
	}
	id, err := resolveServerIDByName(name, tok)
	if err != nil {
		respondEphemeral(s, i, "❌ "+err.Error())
		return
	}
	respondThinking(s, i)
	if err := postBackup(id, backupName, ignored, lock, tok); err != nil {
		editFollowup(s, i, fmt.Sprintf("❌ backup failed: %v", err))
		return
	}
	// confirmation embed
	fields := []*discordgo.MessageEmbedField{
		{Name: "Server", Value: fmt.Sprintf("**%s**\n`%s`", name, id), Inline: true},
	}
	if strings.TrimSpace(backupName) != "" {
		fields = append(fields, &discordgo.MessageEmbedField{Name: "Name", Value: backupName, Inline: true})
	}
	if strings.TrimSpace(ignored) != "" {
		// show a preview (first 2 lines) to avoid long messages
		lines := strings.Split(ignored, "\n")
		preview := lines[0]
		if len(lines) > 1 {
			preview = preview + " …"
		}
		fields = append(fields, &discordgo.MessageEmbedField{Name: "Ignored", Value: fmt.Sprintf("`%s`", preview), Inline: true})
	}
	if lock {
		fields = append(fields, &discordgo.MessageEmbedField{Name: "Locked", Value: "true", Inline: true})
	}
	embed := &discordgo.MessageEmbed{
		Title:     "Backup requested",
		Color:     0x57F287,
		Timestamp: time.Now().Format(time.RFC3339),
		Fields:    fields,
	}
	editFollowupEmbed(s, i, embed)
}

// doSetKey saves or clears the caller's personal Pterodactyl API key.
// The token is validated with a lightweight list request and stored
// encrypted-at-rest on the bot host.
func doSetKey(s *discordgo.Session, i *discordgo.InteractionCreate) {
	raw := optionString(i, "value")
	uid := i.Member.User.ID
	if strings.EqualFold(strings.TrimSpace(raw), "clear") || raw == "" {
		clearUserToken(uid)
		// Slightly prettier confirmation
		embed := &discordgo.MessageEmbed{
			Title:       "API key removed",
			Description: "Your personal API key was cleared. The bot will use the default key if configured.",
			Color:       0xED4245,
			Timestamp:   time.Now().Format(time.RFC3339),
		}
		respondEphemeralEmbed(s, i, embed)
		return
	}
	// Defer response to avoid 3s timeout, then validate
	respondThinking(s, i)
	// Save key and make a quick sanity check call to validate it (optional)
	setUserToken(uid, raw)
	if _, err := listServers(raw); err != nil {
		embed := &discordgo.MessageEmbed{
			Title:       "Key saved",
			Description: "Saved, but validation failed: " + err.Error(),
			Color:       0xFEE75C,
			Timestamp:   time.Now().Format(time.RFC3339),
		}
		editFollowupEmbed(s, i, embed)
		return
	}
	embed := &discordgo.MessageEmbed{
		Title:       "Key saved",
		Description: "Your API key was saved and validated.",
		Color:       0x57F287,
		Timestamp:   time.Now().Format(time.RFC3339),
	}
	editFollowupEmbed(s, i, embed)
}

// optionString extracts a string option by name from a subcommand invocation.
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

// optionBool extracts a bool option by name from a subcommand invocation.
func optionBool(i *discordgo.InteractionCreate, name string) bool {
	for _, opt := range i.ApplicationCommandData().Options[0].Options {
		if opt.Name == name {
			if v, ok := opt.Value.(bool); ok {
				return v
			}
		}
	}
	return false
}

// respondEphemeral replies to the interaction with an ephemeral message.
func respondEphemeral(s *discordgo.Session, i *discordgo.InteractionCreate, msg string) {
	_ = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Content: msg, Flags: discordgo.MessageFlagsEphemeral},
	})
}

// respondEphemeralEmbed replies to the interaction with an ephemeral embed.
func respondEphemeralEmbed(s *discordgo.Session, i *discordgo.InteractionCreate, embed *discordgo.MessageEmbed) {
	_ = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Flags:  discordgo.MessageFlagsEphemeral,
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})
}

// respondThinking sends a deferred ephemeral response to indicate processing.
func respondThinking(s *discordgo.Session, i *discordgo.InteractionCreate) {
	_ = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{Flags: discordgo.MessageFlagsEphemeral},
	})
}

// editFollowup edits the deferred ephemeral response with the final content.
func editFollowup(s *discordgo.Session, i *discordgo.InteractionCreate, msg string) {
	_, _ = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{Content: &msg})
}

// editFollowupEmbed edits the deferred response and replaces content with an embed.
func editFollowupEmbed(s *discordgo.Session, i *discordgo.InteractionCreate, embed *discordgo.MessageEmbed) {
	embs := []*discordgo.MessageEmbed{embed}
	_, _ = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{Embeds: &embs})
}

// emoji and color helpers for consistent styling
func stateEmoji(state string, suspended bool) string {
	if suspended {
		return "⏸️"
	}
	switch strings.ToLower(state) {
	case "running", "on":
		return "🟢"
	case "starting":
		return "🟡"
	case "stopping", "offline", "off":
		return "🔴"
	default:
		return "⚪"
	}
}

func boldState(state string, suspended bool) string {
	if suspended {
		return "Suspended"
	}
	s := strings.ToLower(state)
	// capitalize first letter safely
	if s == "" {
		return "**Unknown**"
	}
	r := []rune(s)
	r[0] = toUpperRune(r[0])
	return "**" + string(r) + "**"
}

func toUpperRune(r rune) rune {
	// basic ASCII fast path
	if r >= 'a' && r <= 'z' {
		return r - 32
	}
	return []rune(strings.ToUpper(string(r)))[0]
}

func stateColor(state string, suspended bool) int {
	if suspended {
		return 0x95A5A6
	}
	switch strings.ToLower(state) {
	case "running", "on":
		return 0x57F287
	case "starting":
		return 0xFEE75C
	case "stopping", "offline", "off":
		return 0xED4245
	default:
		return 0x5865F2
	}
}

// reload re-reads the config file and applies in-memory overrides.
func reload() {
	newCfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Printf("reload failed: %v", err)
		return
	}
	config.Store(newCfg)
	log.Printf("🔁 reloaded config")
}

// getCfg returns the current configuration snapshot.
func getCfg() *Config { return config.Load().(*Config) }

// tokenForUserOrError returns a usable token for the user or an instructive error
// when neither a user token nor a valid default token is configured.
func tokenForUserOrError(userID string) (string, error) {
	// Prefer user-specific token if set
	userTokensMu.RLock()
	tok, ok := userTokens[userID]
	userTokensMu.RUnlock()
	if ok && strings.TrimSpace(tok) != "" {
		return tok, nil
	}
	// Fall back to default if present and not a placeholder
	def := strings.TrimSpace(getCfg().PteroClientToken)
	if def == "" || strings.EqualFold(def, "REPLACE_ME_PTERO_TOKEN") {
		return "", errors.New("no API key available. Use /pt key to set your personal key, or configure a default API key for the bot.")
	}
	return def, nil
}

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
			MemoryBytes    float64 `json:"memory_bytes"`
			CPUAbsolute    float64 `json:"cpu_absolute"`
			DiskBytes      float64 `json:"disk_bytes"`
			NetworkRxBytes float64 `json:"network_rx_bytes"`
			NetworkTxBytes float64 `json:"network_tx_bytes"`
		} `json:"resources"`
	} `json:"attributes"`
}

type serverInfo struct {
	ID   string
	Name string
}

// listServers retrieves all visible servers for the provided Pterodactyl token.
func listServers(token string) ([]serverInfo, error) {
	cfg := getCfg()
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("missing API token")
	}
	page := 1
	var out []serverInfo
	for {
		url := strings.TrimRight(cfg.PteroBaseURL, "/") + fmt.Sprintf("/api/client?page=%d&per_page=100", page)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+token)
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

// resolveServerIDByName matches a server by exact or unique prefix under the
// provided token and returns its identifier or an error if ambiguous/missing.
func resolveServerIDByName(input string, token string) (string, error) {
	if strings.TrimSpace(input) == "" {
		return "", errors.New("server name is required")
	}
	servers, err := listServers(token)
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

// getResources returns live resource stats for a server id using the token.
func getResources(id string, token string) (*resourcesResp, error) {
	url := strings.TrimRight(getCfg().PteroBaseURL, "/") + "/api/client/servers/" + id + "/resources"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
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

// postPower issues a power signal (start/stop/restart) for a server id.
func postPower(id, signal string, token string) error {
	url := strings.TrimRight(getCfg().PteroBaseURL, "/") + "/api/client/servers/" + id + "/power"
	body := map[string]string{"signal": signal}
	j, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(j))
	req.Header.Set("Authorization", "Bearer "+token)
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

// postCommand sends a console command to the server using the token.
func postCommand(id, cmd string, token string) error {
	url := strings.TrimRight(getCfg().PteroBaseURL, "/") + "/api/client/servers/" + id + "/command"
	body := map[string]string{"command": cmd}
	j, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(j))
	req.Header.Set("Authorization", "Bearer "+token)
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

// postBackup requests a new backup for the server via Pterodactyl client API.
// Endpoint: POST /api/client/servers/{id}/backups with optional {name: label}
func postBackup(id, label, ignored string, lock bool, token string) error {
	url := strings.TrimRight(getCfg().PteroBaseURL, "/") + "/api/client/servers/" + id + "/backups"
	body := map[string]any{}
	if strings.TrimSpace(label) != "" {
		body["name"] = label
	}
	if strings.TrimSpace(ignored) != "" {
		body["ignored"] = ignored
	}
	if lock {
		body["is_locked"] = true
	}
	j, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(j))
	req.Header.Set("Authorization", "Bearer "+token)
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

// onceAlert ensures we only send one alert per failure period.
var onceAlert sync.Once

// lastHealth tracks the last known health state to detect recovery events.
var lastHealth atomic.Bool

// healthLoop periodically checks the panel health and emits a Discord alert
// once per failure period.
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
				// mark unhealthy so we can detect recovery later
				lastHealth.Store(false)
			} else {
				// if we were previously unhealthy, notify recovery
				if !lastHealth.Load() {
					notifyRecovery()
				}
				// mark healthy and reset failure guard
				lastHealth.Store(true)
				onceAlert = sync.Once{}
			}
		}
	}
}

// checkPanelHealth probes the Pterodactyl /account endpoint using the bot's
// default client token and returns an error if unhealthy.
func checkPanelHealth() error {
	cfg := getCfg()
	// If default token is missing or placeholder, emit instructive error
	if strings.TrimSpace(cfg.PteroClientToken) == "" || strings.EqualFold(strings.TrimSpace(cfg.PteroClientToken), "REPLACE_ME_PTERO_TOKEN") {
		return errors.New("default API key not set. Set PTERO_CLIENT_TOKEN in config/env or have users run /pt key to set their own.")
	}
	url := strings.TrimRight(cfg.PteroBaseURL, "/") + "/api/client/account"
	req, _ := http.NewRequest("GET", url, nil)
	// Health check uses the default token from config
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

// alert posts a single alert message to the configured channel until health
// recovers, at which point the alert guard resets.
func alert(msg string) {
	cfg := getCfg()
	if cfg.AlertChannelID == "" || sess == nil {
		return
	}
	onceAlert.Do(func() {
		_, _ = sess.ChannelMessageSend(cfg.AlertChannelID, "⚠️ Pterodactyl health check failed: "+msg)
	})
}

// notifyRecovery posts a message when the panel transitions
// from unhealthy back to healthy.
func notifyRecovery() {
	cfg := getCfg()
	if cfg.AlertChannelID == "" || sess == nil {
		return
	}
	_, _ = sess.ChannelMessageSend(cfg.AlertChannelID, "✅ Pterodactyl panel is back online.")
}

// ---------- utils ----------

// loadConfig loads configuration from the given path, creating a default
// config from environment variables if missing, and applies env overrides.
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
	if v := os.Getenv("DISCORD_TOKEN"); v != "" {
		c.DiscordToken = v
	}
	if v := os.Getenv("PTERO_BASE_URL"); v != "" {
		c.PteroBaseURL = v
	}
	if v := os.Getenv("PTERO_CLIENT_TOKEN"); v != "" {
		c.PteroClientToken = v
	}
	if v := os.Getenv("ALERT_CHANNEL_ID"); v != "" {
		c.AlertChannelID = v
	}
	if v := os.Getenv("HEALTH_CHECK_INTERVAL"); v != "" {
		c.HealthCheckInterval = v
	}

	// CSV allowlists via env (override arrays if provided)
	if v := os.Getenv("ALLOWED_GUILD_IDS"); v != "" {
		c.AllowedGuildIDs = parseCSV(v)
	}
	if v := os.Getenv("ALLOWED_ROLE_IDS"); v != "" {
		c.AllowedRoleIDs = parseCSV(v)
	}
	if v := os.Getenv("ALLOWED_USER_IDS"); v != "" {
		c.AllowedUserIDs = parseCSV(v)
	}

	// Warn if still placeholders
	if c.DiscordToken == "" || c.PteroBaseURL == "" || c.PteroClientToken == "" ||
		c.DiscordToken == "REPLACE_ME_DISCORD_TOKEN" || c.PteroClientToken == "REPLACE_ME_PTERO_TOKEN" {
		log.Println("⚠️ Warning: required fields may be placeholders; bot will not function until updated.")
	}
	return &c, nil
}

// writeConfigFromEnv materializes a config file using environment variables
// or placeholders when the file does not exist.
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

// envOrDefault returns the trimmed environment value or the provided default.
func envOrDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// parseDurDefault parses a duration string or returns the default if invalid.
func parseDurDefault(s string, d time.Duration) time.Duration {
	if s == "" {
		return d
	}
	if v, err := time.ParseDuration(s); err == nil {
		return v
	}
	return d
}

// parseCSV splits a comma-separated string into a trimmed slice, filtering blanks.
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

// ternary returns a if cond is true, otherwise b (generic helper).
func ternary[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}

// ---------- per-user token storage ----------

const userTokensPath = "/data/user_tokens.json"
const userTokensKeyPath = "/data/user_tokens.key"
const envTokensSecret = "PTBOT_TOKENS_SECRET"

// effectiveToken returns the token to use for a given Discord user ID,
// falling back to the default from config when none is set.
func effectiveToken(userID string) string {
	userTokensMu.RLock()
	tok, ok := userTokens[userID]
	userTokensMu.RUnlock()
	if ok && strings.TrimSpace(tok) != "" {
		return tok
	}
	return getCfg().PteroClientToken
}

// setUserToken stores the token in memory for the user and persists to disk.
func setUserToken(userID, token string) {
	userTokensMu.Lock()
	if userTokens == nil {
		userTokens = map[string]string{}
	}
	userTokens[userID] = strings.TrimSpace(token)
	userTokensMu.Unlock()
	_ = saveUserTokens()
}

// clearUserToken removes a stored token for the user and persists changes.
func clearUserToken(userID string) {
	userTokensMu.Lock()
	if userTokens != nil {
		delete(userTokens, userID)
	}
	userTokensMu.Unlock()
	_ = saveUserTokens()
}

// Encrypted on-disk structure
type encUserTokens struct {
	Version int               `json:"version"`
	Salt    string            `json:"salt"` // base64(salt) for passphrase-derived keys
	Data    map[string]string `json:"data"` // userID -> base64(nonce|ciphertext)
}

var (
	encKey  []byte // 32 bytes
	encSalt []byte // salt used with passphrase-derived key
)

// ensureEncKeyForLoad prepares the encryption key for decrypting tokens based
// on available inputs: a passphrase-derived key (with provided salt) or a
// file key stored at userTokensKeyPath.
func ensureEncKeyForLoad(existingSalt []byte) error {
	if encKey != nil {
		return nil
	}
	// 1) If passphrase provided, derive using existing salt
	if pass := strings.TrimSpace(os.Getenv(envTokensSecret)); pass != "" {
		if len(existingSalt) == 0 {
			return errors.New("encrypted tokens file missing salt; cannot derive key from passphrase")
		}
		key, err := scrypt.Key([]byte(pass), existingSalt, 1<<15, 8, 1, 32)
		if err != nil {
			return err
		}
		encKey, encSalt = key, existingSalt
		return nil
	}
	// 2) Try key file (raw 32-byte key)
	if kb, err := os.ReadFile(userTokensKeyPath); err == nil {
		if len(kb) != 32 {
			return fmt.Errorf("invalid key length in %s", userTokensKeyPath)
		}
		encKey = kb
		return nil
	}
	// No key available -> cannot decrypt existing data
	return errors.New("no token decryption key found; set PTBOT_TOKENS_SECRET or place 32-byte key in /data/user_tokens.key")
}

// ensureEncKeyForSave ensures an encryption key is available for saving. It
// prefers a passphrase-derived key (emitting a new salt if needed) and falls
// back to a file key (creating one if absent).
func ensureEncKeyForSave() error {
	if encKey != nil {
		return nil
	}
	// Prefer passphrase if provided
	if pass := strings.TrimSpace(os.Getenv(envTokensSecret)); pass != "" {
		if len(encSalt) == 0 {
			// generate new salt
			encSalt = make([]byte, 16)
			if _, err := rand.Read(encSalt); err != nil {
				return err
			}
		}
		key, err := scrypt.Key([]byte(pass), encSalt, 1<<15, 8, 1, 32)
		if err != nil {
			return err
		}
		encKey = key
		return nil
	}
	// Fallback to (or create) key file
	if kb, err := os.ReadFile(userTokensKeyPath); err == nil {
		if len(kb) != 32 {
			return fmt.Errorf("invalid key length in %s", userTokensKeyPath)
		}
		encKey = kb
		return nil
	}
	// create new random key and write it
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(userTokensKeyPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(userTokensKeyPath, key, 0o600); err != nil {
		return err
	}
	encKey = key
	return nil
}

// encryptValue seals the plaintext using AES-GCM and returns base64(nonce|ct).
func encryptValue(plain string) (string, error) {
	if err := ensureEncKeyForSave(); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, []byte(plain), nil)
	out := append(nonce, ct...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// decryptValue decodes base64(nonce|ct) and opens it with AES-GCM.
func decryptValue(b64 string) (string, error) {
	// encKey must already be available (ensureEncKeyForLoad called by loader with salt context)
	if encKey == nil {
		return "", errors.New("encryption key not initialized")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return "", errors.New("ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// loadUserTokens loads the user token map from disk, supporting both the
// encrypted format and legacy plaintext; legacy is migrated on save.
func loadUserTokens() error {
	b, err := os.ReadFile(userTokensPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			userTokens = map[string]string{}
			return nil
		}
		return err
	}
	// First, try encrypted format
	var enc encUserTokens
	if err := json.Unmarshal(b, &enc); err == nil && enc.Version == 1 {
		// initialize key for decryption
		if enc.Salt != "" {
			if salt, err := base64.StdEncoding.DecodeString(enc.Salt); err == nil {
				encSalt = salt
			}
		}
		if err := ensureEncKeyForLoad(encSalt); err != nil {
			return err
		}
		out := make(map[string]string, len(enc.Data))
		for uid, ctb64 := range enc.Data {
			pt, err := decryptValue(ctb64)
			if err != nil {
				return fmt.Errorf("decrypt token for %s: %w", uid, err)
			}
			out[uid] = pt
		}
		userTokensMu.Lock()
		userTokens = out
		userTokensMu.Unlock()
		return nil
	}
	// Backward compatibility: plaintext map
	var plain map[string]string
	if err := json.Unmarshal(b, &plain); err != nil {
		return fmt.Errorf("read user tokens: %w", err)
	}
	userTokensMu.Lock()
	userTokens = plain
	userTokensMu.Unlock()
	// Attempt migration to encrypted format (best-effort)
	if err := saveUserTokens(); err != nil {
		log.Printf("warning: failed to migrate user tokens to encrypted format: %v", err)
	}
	return nil
}

// saveUserTokens persists the in-memory user token map using encrypted
// storage with per-value nonces and versioned metadata.
func saveUserTokens() error {
	// ensure dir
	if err := os.MkdirAll(filepath.Dir(userTokensPath), 0o755); err != nil {
		return err
	}
	userTokensMu.RLock()
	m := userTokens
	userTokensMu.RUnlock()
	if m == nil {
		m = map[string]string{}
	}
	if err := ensureEncKeyForSave(); err != nil {
		return err
	}
	encMap := make(map[string]string, len(m))
	for uid, tok := range m {
		ctb64, err := encryptValue(tok)
		if err != nil {
			return err
		}
		encMap[uid] = ctb64
	}
	out := encUserTokens{Version: 1, Data: encMap}
	if len(encSalt) > 0 {
		out.Salt = base64.StdEncoding.EncodeToString(encSalt)
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return os.WriteFile(userTokensPath, b, 0o600)
}

// Initialize file-based encryption key at startup when appropriate.
// Rules:
// - If PTBOT_TOKENS_SECRET is set, we don't generate a file key.
// - If user_tokens.key exists, keep it.
// - If user_tokens.json does not exist or is plaintext, generate a new file key.
// - If user_tokens.json is encrypted and appears to need a pre-existing key or passphrase, do not generate a new key.
// initTokenEncryptionKey ensures a file-based key is present when safe.
// It never overwrites or generates a new key if decryption of existing
// encrypted data would require the original key or a passphrase.
func initTokenEncryptionKey() error {
	// Passphrase in env -> no file key generation needed
	if strings.TrimSpace(os.Getenv(envTokensSecret)) != "" {
		return nil
	}
	// If key file exists, we're good
	if fi, err := os.Stat(userTokensKeyPath); err == nil && !fi.IsDir() {
		return nil
	}
	// Check tokens file
	b, err := os.ReadFile(userTokensPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No tokens yet -> safe to generate a key for future use
			return generateFileKey()
		}
		return err
	}
	// Try encrypted format
	var enc encUserTokens
	if json.Unmarshal(b, &enc) == nil && enc.Version == 1 {
		// If Salt is empty, this likely used a file-based key before.
		// We must not generate a new random key if the original is missing; operator must restore it.
		// If Salt is present, it was passphrase-derived; operator must set PTBOT_TOKENS_SECRET.
		return nil
	}
	// Plaintext tokens file -> safe to generate a file key now
	return generateFileKey()
}

// generateFileKey creates a new random 32-byte key at userTokensKeyPath.
func generateFileKey() error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(userTokensKeyPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(userTokensKeyPath, key, 0o600)
}
