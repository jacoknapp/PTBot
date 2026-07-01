package main

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
	"golang.org/x/crypto/scrypt"
)

// ---------- test helpers ----------

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

// resetCrypto zeroes and clears package-level encryption key globals between tests.
func resetCrypto() {
	for i := range encKey {
		encKey[i] = 0
	}
	encKey = nil
	encSalt = nil
}

// encryptWithKey encrypts plain using AES-GCM with a caller-supplied key.
// Used in tests to manufacture files encrypted with specific parameters (e.g. old scrypt N).
func encryptWithKey(key []byte, plain string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := crand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(append(nonce, ct...)), nil
}

// makeInteraction builds a minimal InteractionCreate for allowlist tests.
func makeInteraction(guildID, channelID, userID string, roles []string) *discordgo.InteractionCreate {
	return &discordgo.InteractionCreate{
		Interaction: &discordgo.Interaction{
			GuildID:   guildID,
			ChannelID: channelID,
			Member: &discordgo.Member{
				User:  &discordgo.User{ID: userID},
				Roles: roles,
			},
		},
	}
}

// ---------- pure helper unit tests ----------

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

func TestStateEmoji(t *testing.T) {
	cases := []struct {
		state     string
		suspended bool
		want      string
	}{
		{"running", false, "🟢"},
		{"on", false, "🟢"},
		{"starting", false, "🟡"},
		{"stopping", false, "🔴"},
		{"offline", false, "🔴"},
		{"off", false, "🔴"},
		{"unknown", false, "⚪"},
		{"running", true, "⏸️"},
		{"", true, "⏸️"},
	}
	for _, c := range cases {
		if got := stateEmoji(c.state, c.suspended); got != c.want {
			t.Errorf("stateEmoji(%q,%v)=%q want %q", c.state, c.suspended, got, c.want)
		}
	}
}

func TestBoldState(t *testing.T) {
	if got := boldState("running", false); got != "**Running**" {
		t.Fatalf("boldState running: %q", got)
	}
	if got := boldState("offline", false); got != "**Offline**" {
		t.Fatalf("boldState offline: %q", got)
	}
	if got := boldState("", true); got != "Suspended" {
		t.Fatalf("boldState suspended: %q", got)
	}
	if got := boldState("", false); got != "**Unknown**" {
		t.Fatalf("boldState empty: %q", got)
	}
}

func TestStateColor(t *testing.T) {
	if stateColor("running", false) != 0x57F287 {
		t.Fatal("running color wrong")
	}
	if stateColor("on", false) != 0x57F287 {
		t.Fatal("on color wrong")
	}
	if stateColor("starting", false) != 0xFEE75C {
		t.Fatal("starting color wrong")
	}
	if stateColor("offline", false) != 0xED4245 {
		t.Fatal("offline color wrong")
	}
	if stateColor("anything", true) != 0x95A5A6 {
		t.Fatal("suspended color wrong")
	}
	if stateColor("other", false) != 0x5865F2 {
		t.Fatal("default color wrong")
	}
}

func TestToUpperRune(t *testing.T) {
	if toUpperRune('a') != 'A' {
		t.Fatal("ascii lower->upper failed")
	}
	if toUpperRune('z') != 'Z' {
		t.Fatal("ascii z->Z failed")
	}
	if toUpperRune('A') != 'A' {
		t.Fatal("already upper should be unchanged")
	}
	if toUpperRune('0') != '0' {
		t.Fatal("digit should be unchanged")
	}
}

func TestUserDisplayName(t *testing.T) {
	if userDisplayName(nil) != "unknown" {
		t.Fatal("nil member should return 'unknown'")
	}
	if userDisplayName(&discordgo.Member{}) != "unknown" {
		t.Fatal("member with nil user should return 'unknown'")
	}
	m := &discordgo.Member{Nick: "NickName", User: &discordgo.User{Username: "user123", ID: "111"}}
	if userDisplayName(m) != "NickName" {
		t.Fatal("nick should take priority")
	}
	m.Nick = "   "
	if userDisplayName(m) != "user123" {
		t.Fatal("whitespace-only nick should fall back to username")
	}
	m.User.Username = ""
	if userDisplayName(m) != "111" {
		t.Fatal("empty username should fall back to ID")
	}
}

// ---------- token / config logic tests ----------

func TestEffectiveTokenSetAndClear(t *testing.T) {
	config.Store(&Config{PteroClientToken: "default"})
	userTokensMu.Lock()
	userTokens = map[string]string{}
	userTokensMu.Unlock()

	uid := "123"
	tok, err := tokenForUserOrError(uid)
	if err != nil || tok != "default" {
		t.Fatalf("tokenForUserOrError fallback=%q err=%v want default", tok, err)
	}
	setUserToken(uid, "abc")
	tok, err = tokenForUserOrError(uid)
	if err != nil || tok != "abc" {
		t.Fatalf("tokenForUserOrError set=%q err=%v want abc", tok, err)
	}
	clearUserToken(uid)
	tok, err = tokenForUserOrError(uid)
	if err != nil || tok != "default" {
		t.Fatalf("tokenForUserOrError cleared=%q err=%v want default", tok, err)
	}
}

func TestTokenForUserOrError(t *testing.T) {
	userTokensMu.Lock()
	userTokens = map[string]string{}
	userTokensMu.Unlock()

	config.Store(&Config{PteroClientToken: "default"})
	setUserToken("u1", "per-user")
	tok, err := tokenForUserOrError("u1")
	if err != nil || tok != "per-user" {
		t.Fatalf("expected per-user token, got tok=%q err=%v", tok, err)
	}

	clearUserToken("u1")
	config.Store(&Config{PteroClientToken: "default-real"})
	tok, err = tokenForUserOrError("u1")
	if err != nil || tok != "default-real" {
		t.Fatalf("expected default token, got tok=%q err=%v", tok, err)
	}

	config.Store(&Config{PteroClientToken: ""})
	tok, err = tokenForUserOrError("u2")
	if err == nil || !strings.Contains(err.Error(), "no API key available") {
		t.Fatalf("expected missing token error, got tok=%q err=%v", tok, err)
	}

	config.Store(&Config{PteroClientToken: "REPLACE_ME_PTERO_TOKEN"})
	tok, err = tokenForUserOrError("u3")
	if err == nil || !strings.Contains(err.Error(), "no API key available") {
		t.Fatalf("expected placeholder error, got tok=%q err=%v", tok, err)
	}
}

// ---------- config bootstrap tests ----------

func TestWriteConfigFromEnvAndLoad(t *testing.T) {
	tmp := t.TempDir()
	cfgFile := filepath.Join(tmp, "config.json")

	withEnv("DISCORD_TOKEN", "env_discord", func() {
		withEnv("PTERO_BASE_URL", "https://panel.example.com", func() {
			withEnv("PTERO_CLIENT_TOKEN", "env_ptero", func() {
				withEnv("HEALTH_CHECK_INTERVAL", "1m", func() {
					cfg, err := loadConfig(cfgFile)
					if err != nil {
						t.Fatalf("loadConfig: %v", err)
					}
					if _, err := os.Stat(cfgFile); err != nil {
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
					raw, _ := os.ReadFile(cfgFile)
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
	cfgFile := filepath.Join(tmp, "config.json")

	cfg, err := loadConfig(cfgFile)
	if err != nil {
		t.Fatalf("loadConfig (placeholders): %v", err)
	}
	if cfg.DiscordToken == "" || cfg.PteroClientToken == "" {
		t.Fatalf("placeholders not set in memory")
	}
	raw, _ := os.ReadFile(cfgFile)
	s := string(raw)
	if !strings.Contains(s, "REPLACE_ME_DISCORD_TOKEN") || !strings.Contains(s, "REPLACE_ME_PTERO_TOKEN") {
		t.Fatalf("expected placeholder values written to file, got: %s", s)
	}
}

func TestReload(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")
	initial := Config{
		DiscordToken:     "tok1",
		PteroBaseURL:     "https://panel.example.com",
		PteroClientToken: "ptok1",
	}
	b, _ := json.MarshalIndent(initial, "", "  ")
	os.WriteFile(path, b, 0o640)

	savedPath := *cfgPath
	*cfgPath = path
	defer func() { *cfgPath = savedPath }()

	config.Store(&initial)
	updated := initial
	updated.DiscordToken = "tok2"
	b2, _ := json.MarshalIndent(updated, "", "  ")
	os.WriteFile(path, b2, 0o640)

	reload()
	if getCfg().DiscordToken != "tok2" {
		t.Fatalf("reload did not update config: got %q", getCfg().DiscordToken)
	}
}

// ---------- crypto tests ----------

func TestEncryptDecryptRoundtrip(t *testing.T) {
	tmp := t.TempDir()
	userTokensKeyPath = filepath.Join(tmp, "test.key")
	resetCrypto()
	defer resetCrypto()
	defer func() { userTokensKeyPath = "/data/user_tokens.key" }()

	plain := "ptla_secret-token-value_abc123"
	ct, err := encryptValue(plain)
	if err != nil {
		t.Fatalf("encryptValue: %v", err)
	}
	got, err := decryptValue(ct)
	if err != nil {
		t.Fatalf("decryptValue: %v", err)
	}
	if got != plain {
		t.Fatalf("roundtrip: got %q want %q", got, plain)
	}
}

func TestEncryptProducesUniqueNonces(t *testing.T) {
	tmp := t.TempDir()
	userTokensKeyPath = filepath.Join(tmp, "test.key")
	resetCrypto()
	defer resetCrypto()
	defer func() { userTokensKeyPath = "/data/user_tokens.key" }()

	a, _ := encryptValue("same-value")
	b, _ := encryptValue("same-value")
	if a == b {
		t.Fatal("two encryptions of same plaintext produced identical ciphertext (nonce reuse)")
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	tmp := t.TempDir()
	userTokensKeyPath = filepath.Join(tmp, "test.key")
	resetCrypto()
	defer resetCrypto()
	defer func() { userTokensKeyPath = "/data/user_tokens.key" }()

	ct, _ := encryptValue("secret")
	raw, _ := base64.StdEncoding.DecodeString(ct)
	raw[len(raw)-1] ^= 0xFF
	tampered := base64.StdEncoding.EncodeToString(raw)
	if _, err := decryptValue(tampered); err == nil {
		t.Fatal("expected authentication error on tampered ciphertext")
	}
}

func TestDecryptTooShort(t *testing.T) {
	tmp := t.TempDir()
	userTokensKeyPath = filepath.Join(tmp, "test.key")
	resetCrypto()
	defer resetCrypto()
	defer func() { userTokensKeyPath = "/data/user_tokens.key" }()

	// Ensure key is set before decrypt
	encryptValue("prime-key")
	tooShort := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02})
	if _, err := decryptValue(tooShort); err == nil {
		t.Fatal("expected error for too-short ciphertext")
	}
}

// ---------- key management tests ----------

func TestGenerateFileKey(t *testing.T) {
	tmp := t.TempDir()
	userTokensKeyPath = filepath.Join(tmp, "tokens.key")
	defer func() { userTokensKeyPath = "/data/user_tokens.key" }()

	if err := generateFileKey(); err != nil {
		t.Fatalf("generateFileKey: %v", err)
	}
	b, err := os.ReadFile(userTokensKeyPath)
	if err != nil {
		t.Fatalf("key file missing: %v", err)
	}
	if len(b) != 32 {
		t.Fatalf("key length=%d want 32", len(b))
	}
	fi, _ := os.Stat(userTokensKeyPath)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file perm=%o want 0600", fi.Mode().Perm())
	}
}

func TestEnsureEncKeyForSave_CreatesFileKey(t *testing.T) {
	tmp := t.TempDir()
	userTokensKeyPath = filepath.Join(tmp, "tokens.key")
	resetCrypto()
	defer resetCrypto()
	defer func() { userTokensKeyPath = "/data/user_tokens.key" }()

	if err := ensureEncKeyForSave(); err != nil {
		t.Fatalf("ensureEncKeyForSave: %v", err)
	}
	if len(encKey) != 32 {
		t.Fatalf("encKey len=%d want 32", len(encKey))
	}
	if _, err := os.Stat(userTokensKeyPath); err != nil {
		t.Fatalf("key file not created: %v", err)
	}
	// idempotent: second call must not change the key
	saved := make([]byte, 32)
	copy(saved, encKey)
	if err := ensureEncKeyForSave(); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if string(encKey) != string(saved) {
		t.Fatal("second call changed encKey")
	}
}

func TestEnsureEncKeyForSave_Passphrase(t *testing.T) {
	resetCrypto()
	defer resetCrypto()
	withEnv("PTBOT_TOKENS_SECRET", "hunter2", func() {
		if err := ensureEncKeyForSave(); err != nil {
			t.Fatalf("ensureEncKeyForSave passphrase: %v", err)
		}
		if len(encKey) != 32 {
			t.Fatalf("encKey len=%d want 32", len(encKey))
		}
		if len(encSalt) == 0 {
			t.Fatal("encSalt not populated")
		}
	})
}

func TestEnsureEncKeyForLoad_FileKey(t *testing.T) {
	tmp := t.TempDir()
	userTokensKeyPath = filepath.Join(tmp, "tokens.key")
	resetCrypto()
	defer resetCrypto()
	defer func() { userTokensKeyPath = "/data/user_tokens.key" }()

	key := make([]byte, 32)
	crand.Read(key)
	os.WriteFile(userTokensKeyPath, key, 0o600)

	if err := ensureEncKeyForLoad(nil, scryptN); err != nil {
		t.Fatalf("ensureEncKeyForLoad file key: %v", err)
	}
	if string(encKey) != string(key) {
		t.Fatal("loaded key does not match written key")
	}
}

func TestEnsureEncKeyForLoad_Passphrase(t *testing.T) {
	resetCrypto()
	defer resetCrypto()
	salt := make([]byte, 16)
	crand.Read(salt)
	withEnv("PTBOT_TOKENS_SECRET", "passphrase123", func() {
		if err := ensureEncKeyForLoad(salt, scryptN); err != nil {
			t.Fatalf("ensureEncKeyForLoad passphrase: %v", err)
		}
		if len(encKey) != 32 {
			t.Fatalf("encKey len=%d want 32", len(encKey))
		}
		// deterministic: same pass + salt + N = same key
		saved := make([]byte, 32)
		copy(saved, encKey)
		resetCrypto()
		if err := ensureEncKeyForLoad(salt, scryptN); err != nil {
			t.Fatalf("second call: %v", err)
		}
		if string(encKey) != string(saved) {
			t.Fatal("key derivation not deterministic")
		}
	})
}

func TestEnsureEncKeyForLoad_MissingSalt(t *testing.T) {
	tmp := t.TempDir()
	userTokensKeyPath = filepath.Join(tmp, "nokey.key")
	resetCrypto()
	defer resetCrypto()
	defer func() { userTokensKeyPath = "/data/user_tokens.key" }()

	withEnv("PTBOT_TOKENS_SECRET", "pass", func() {
		err := ensureEncKeyForLoad(nil, scryptN)
		if err == nil || !strings.Contains(err.Error(), "missing salt") {
			t.Fatalf("expected missing salt error, got %v", err)
		}
	})
}

func TestEnsureEncKeyForLoad_NoKeyAvailable(t *testing.T) {
	tmp := t.TempDir()
	userTokensKeyPath = filepath.Join(tmp, "nokey.key")
	resetCrypto()
	defer resetCrypto()
	defer func() { userTokensKeyPath = "/data/user_tokens.key" }()

	// No passphrase and no key file -> error
	err := ensureEncKeyForLoad(nil, scryptN)
	if err == nil || !strings.Contains(err.Error(), "no token decryption key") {
		t.Fatalf("expected no-key error, got %v", err)
	}
}

// ---------- token storage roundtrip tests ----------

func TestSaveLoadUserTokens_FileKey(t *testing.T) {
	tmp := t.TempDir()
	userTokensPath = filepath.Join(tmp, "tokens.json")
	userTokensKeyPath = filepath.Join(tmp, "tokens.key")
	resetCrypto()
	defer resetCrypto()
	defer func() {
		userTokensPath = "/data/user_tokens.json"
		userTokensKeyPath = "/data/user_tokens.key"
	}()

	userTokensMu.Lock()
	userTokens = map[string]string{"u1": "tok-abc", "u2": "tok-xyz"}
	userTokensMu.Unlock()

	if err := saveUserTokens(); err != nil {
		t.Fatalf("saveUserTokens: %v", err)
	}
	// File must be encrypted, not plaintext map
	raw, _ := os.ReadFile(userTokensPath)
	var enc encUserTokens
	if err := json.Unmarshal(raw, &enc); err != nil || enc.Version != 1 {
		t.Fatalf("file not encrypted format: %s", raw)
	}
	if enc.ScryptN != scryptN {
		t.Fatalf("ScryptN=%d want %d", enc.ScryptN, scryptN)
	}
	fi, _ := os.Stat(userTokensPath)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("token file perm=%o want 0600", fi.Mode().Perm())
	}

	// Reload and verify roundtrip
	resetCrypto()
	userTokensMu.Lock()
	userTokens = nil
	userTokensMu.Unlock()

	if err := loadUserTokens(); err != nil {
		t.Fatalf("loadUserTokens: %v", err)
	}
	userTokensMu.RLock()
	defer userTokensMu.RUnlock()
	if userTokens["u1"] != "tok-abc" || userTokens["u2"] != "tok-xyz" {
		t.Fatalf("roundtrip mismatch: %v", userTokens)
	}
}

func TestSaveLoadUserTokens_Passphrase(t *testing.T) {
	tmp := t.TempDir()
	userTokensPath = filepath.Join(tmp, "tokens.json")
	userTokensKeyPath = filepath.Join(tmp, "tokens.key")
	resetCrypto()
	defer resetCrypto()
	defer func() {
		userTokensPath = "/data/user_tokens.json"
		userTokensKeyPath = "/data/user_tokens.key"
	}()

	withEnv("PTBOT_TOKENS_SECRET", "supersecret", func() {
		userTokensMu.Lock()
		userTokens = map[string]string{"alice": "ptla_token123"}
		userTokensMu.Unlock()

		if err := saveUserTokens(); err != nil {
			t.Fatalf("saveUserTokens: %v", err)
		}
		raw, _ := os.ReadFile(userTokensPath)
		var enc encUserTokens
		json.Unmarshal(raw, &enc)
		if enc.Salt == "" {
			t.Fatal("salt not written for passphrase-derived key")
		}
		if enc.ScryptN != scryptN {
			t.Fatalf("ScryptN=%d want %d", enc.ScryptN, scryptN)
		}

		resetCrypto()
		userTokensMu.Lock()
		userTokens = nil
		userTokensMu.Unlock()
		if err := loadUserTokens(); err != nil {
			t.Fatalf("loadUserTokens: %v", err)
		}
		userTokensMu.RLock()
		defer userTokensMu.RUnlock()
		if userTokens["alice"] != "ptla_token123" {
			t.Fatalf("roundtrip: got %v", userTokens)
		}
	})
}

func TestLoadUserTokens_NotExist(t *testing.T) {
	tmp := t.TempDir()
	userTokensPath = filepath.Join(tmp, "nofile.json")
	defer func() { userTokensPath = "/data/user_tokens.json" }()

	userTokensMu.Lock()
	userTokens = nil
	userTokensMu.Unlock()

	if err := loadUserTokens(); err != nil {
		t.Fatalf("loadUserTokens missing file: %v", err)
	}
	userTokensMu.RLock()
	defer userTokensMu.RUnlock()
	if userTokens == nil {
		t.Fatal("expected empty map, got nil")
	}
}

func TestLoadUserTokens_PlaintextMigration(t *testing.T) {
	tmp := t.TempDir()
	userTokensPath = filepath.Join(tmp, "tokens.json")
	userTokensKeyPath = filepath.Join(tmp, "tokens.key")
	resetCrypto()
	defer resetCrypto()
	defer func() {
		userTokensPath = "/data/user_tokens.json"
		userTokensKeyPath = "/data/user_tokens.key"
	}()

	plain := map[string]string{"legacy-user": "plain-tok"}
	b, _ := json.Marshal(plain)
	os.WriteFile(userTokensPath, b, 0o600)

	userTokensMu.Lock()
	userTokens = nil
	userTokensMu.Unlock()

	if err := loadUserTokens(); err != nil {
		t.Fatalf("loadUserTokens plaintext: %v", err)
	}
	userTokensMu.RLock()
	if userTokens["legacy-user"] != "plain-tok" {
		t.Fatalf("plaintext load: got %v", userTokens)
	}
	userTokensMu.RUnlock()

	// File should now be encrypted
	raw, _ := os.ReadFile(userTokensPath)
	var enc encUserTokens
	if json.Unmarshal(raw, &enc) != nil || enc.Version != 1 {
		t.Fatalf("migration did not produce encrypted file: %s", raw)
	}
}

func TestLoadUserTokens_ScryptMigration(t *testing.T) {
	tmp := t.TempDir()
	userTokensPath = filepath.Join(tmp, "tokens.json")
	userTokensKeyPath = filepath.Join(tmp, "tokens.key")
	resetCrypto()
	defer resetCrypto()
	defer func() {
		userTokensPath = "/data/user_tokens.json"
		userTokensKeyPath = "/data/user_tokens.key"
	}()

	withEnv("PTBOT_TOKENS_SECRET", "migrate-me", func() {
		// Build a file encrypted with the old N=1<<15
		salt := make([]byte, 16)
		crand.Read(salt)
		oldKey, _ := scrypt.Key([]byte("migrate-me"), salt, 1<<15, 8, 1, 32)
		ct, _ := encryptWithKey(oldKey, "old-token-value")
		oldFile := encUserTokens{
			Version: 1,
			ScryptN: 0, // 0 = legacy 1<<15
			Salt:    base64.StdEncoding.EncodeToString(salt),
			Data:    map[string]string{"migrating-user": ct},
		}
		b, _ := json.MarshalIndent(oldFile, "", "  ")
		os.WriteFile(userTokensPath, b, 0o600)

		userTokensMu.Lock()
		userTokens = nil
		userTokensMu.Unlock()

		if err := loadUserTokens(); err != nil {
			t.Fatalf("loadUserTokens scrypt migration: %v", err)
		}
		userTokensMu.RLock()
		got := userTokens["migrating-user"]
		userTokensMu.RUnlock()
		if got != "old-token-value" {
			t.Fatalf("migration preserved wrong token: %q", got)
		}

		// File should now carry the new N
		raw, _ := os.ReadFile(userTokensPath)
		var enc encUserTokens
		json.Unmarshal(raw, &enc)
		if enc.ScryptN != scryptN {
			t.Fatalf("post-migration ScryptN=%d want %d", enc.ScryptN, scryptN)
		}
	})
}

func TestInitTokenEncryptionKey_NoTokensFile(t *testing.T) {
	tmp := t.TempDir()
	userTokensPath = filepath.Join(tmp, "tokens.json")
	userTokensKeyPath = filepath.Join(tmp, "tokens.key")
	resetCrypto()
	defer resetCrypto()
	defer func() {
		userTokensPath = "/data/user_tokens.json"
		userTokensKeyPath = "/data/user_tokens.key"
	}()

	if err := initTokenEncryptionKey(); err != nil {
		t.Fatalf("initTokenEncryptionKey: %v", err)
	}
	if _, err := os.Stat(userTokensKeyPath); err != nil {
		t.Fatal("key file not created when no tokens file exists")
	}
}

func TestInitTokenEncryptionKey_PassphraseSkipsFileKey(t *testing.T) {
	tmp := t.TempDir()
	userTokensPath = filepath.Join(tmp, "tokens.json")
	userTokensKeyPath = filepath.Join(tmp, "tokens.key")
	defer func() {
		userTokensPath = "/data/user_tokens.json"
		userTokensKeyPath = "/data/user_tokens.key"
	}()

	withEnv("PTBOT_TOKENS_SECRET", "haspassphrase", func() {
		if err := initTokenEncryptionKey(); err != nil {
			t.Fatalf("initTokenEncryptionKey passphrase: %v", err)
		}
		// Key file must NOT be created when passphrase env is set
		if _, err := os.Stat(userTokensKeyPath); err == nil {
			t.Fatal("key file should NOT be created when PTBOT_TOKENS_SECRET is set")
		}
	})
}

// ---------- autocomplete cache tests ----------

func TestCachedListServers_CacheHit(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		resp := serverListResp{}
		resp.Meta.Pagination.CurrentPage = 1
		resp.Meta.Pagination.TotalPages = 1
		resp.Data = append(resp.Data, struct {
			Object     string `json:"object"`
			Attributes struct {
				Identifier string `json:"identifier"`
				Name       string `json:"name"`
			} `json:"attributes"`
		}{Object: "server", Attributes: struct {
			Identifier string `json:"identifier"`
			Name       string `json:"name"`
		}{Identifier: "aaa", Name: "cached-server"}})
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()
	config.Store(&Config{PteroBaseURL: srv.URL})

	token := "cache-hit-tok"
	serverCacheMu.Lock()
	delete(serverCache, token)
	serverCacheMu.Unlock()

	s1, err := cachedListServers(token)
	if err != nil || len(s1) != 1 {
		t.Fatalf("first call: %v %v", s1, err)
	}
	s2, err := cachedListServers(token)
	if err != nil || len(s2) != 1 {
		t.Fatalf("second call: %v %v", s2, err)
	}
	if callCount != 1 {
		t.Fatalf("expected 1 HTTP call (cache hit), got %d", callCount)
	}
}

func TestCachedListServers_CacheExpiry(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		resp := serverListResp{}
		resp.Meta.Pagination.CurrentPage = 1
		resp.Meta.Pagination.TotalPages = 1
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()
	config.Store(&Config{PteroBaseURL: srv.URL})

	token := "expiry-tok"
	serverCacheMu.Lock()
	serverCache[token] = serverCacheEntry{
		servers: []serverInfo{{ID: "x", Name: "stale"}},
		expiry:  time.Now().Add(-time.Second), // already expired
	}
	serverCacheMu.Unlock()

	if _, err := cachedListServers(token); err != nil {
		t.Fatalf("cachedListServers expired entry: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("expected 1 HTTP call after cache expiry, got %d", callCount)
	}
}

// ---------- isAllowed tests ----------

func TestIsAllowed_NilMember(t *testing.T) {
	config.Store(&Config{})
	i := &discordgo.InteractionCreate{Interaction: &discordgo.Interaction{GuildID: "g1"}}
	ok, why := isAllowed(i)
	if ok || !strings.Contains(why, "guild interaction") {
		t.Fatalf("nil member should be denied: ok=%v why=%q", ok, why)
	}
}

func TestIsAllowed_NoRestrictions(t *testing.T) {
	config.Store(&Config{})
	i := makeInteraction("g1", "c1", "u1", nil)
	ok, _ := isAllowed(i)
	if !ok {
		t.Fatal("no restrictions should allow all")
	}
}

func TestIsAllowed_GuildBlocked(t *testing.T) {
	config.Store(&Config{AllowedGuildIDs: []string{"allowed-guild"}})
	i := makeInteraction("other-guild", "c1", "u1", nil)
	ok, why := isAllowed(i)
	if ok || !strings.Contains(why, "guild") {
		t.Fatalf("wrong guild should be blocked: ok=%v why=%q", ok, why)
	}
}

func TestIsAllowed_GuildAllowed(t *testing.T) {
	config.Store(&Config{AllowedGuildIDs: []string{"g1"}})
	i := makeInteraction("g1", "c1", "u1", nil)
	ok, _ := isAllowed(i)
	if !ok {
		t.Fatal("correct guild + no role restriction should be allowed")
	}
}

func TestIsAllowed_ChannelBlocked(t *testing.T) {
	config.Store(&Config{AllowedChannelIDs: []string{"chan-ok"}})
	i := makeInteraction("g1", "wrong-chan", "u1", nil)
	ok, why := isAllowed(i)
	if ok || !strings.Contains(why, "channel") {
		t.Fatalf("wrong channel should be blocked: ok=%v why=%q", ok, why)
	}
}

func TestIsAllowed_ChannelAllowed(t *testing.T) {
	config.Store(&Config{AllowedChannelIDs: []string{"chan-ok"}})
	i := makeInteraction("g1", "chan-ok", "u1", nil)
	ok, _ := isAllowed(i)
	if !ok {
		t.Fatal("correct channel should be allowed")
	}
}

func TestIsAllowed_UserAllowlistBypassesRole(t *testing.T) {
	// User in allowlist must be permitted even when role restriction is set and they have no matching role.
	config.Store(&Config{AllowedUserIDs: []string{"vip-user"}, AllowedRoleIDs: []string{"r1"}})
	i := makeInteraction("g1", "c1", "vip-user", nil)
	ok, _ := isAllowed(i)
	if !ok {
		t.Fatal("allowlisted user should bypass role check")
	}
}

func TestIsAllowed_RoleAllowed(t *testing.T) {
	config.Store(&Config{AllowedRoleIDs: []string{"mod-role"}})
	i := makeInteraction("g1", "c1", "u1", []string{"other-role", "mod-role"})
	ok, _ := isAllowed(i)
	if !ok {
		t.Fatal("user with required role should be allowed")
	}
}

func TestIsAllowed_RoleMissing(t *testing.T) {
	config.Store(&Config{AllowedRoleIDs: []string{"mod-role"}})
	i := makeInteraction("g1", "c1", "u1", []string{"pleb-role"})
	ok, why := isAllowed(i)
	if ok || !strings.Contains(why, "role") {
		t.Fatalf("user without required role should be denied: ok=%v why=%q", ok, why)
	}
}

// ---------- HTTP-backed Pterodactyl API tests ----------

func TestListServersAndResolve(t *testing.T) {
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
			_ = json.NewEncoder(w).Encode(resourcesResp{
				Object: "stats",
				Attributes: struct {
					CurrentState string `json:"current_state"`
					IsSuspended  bool   `json:"is_suspended"`
					Resources    struct {
						MemoryBytes    float64 `json:"memory_bytes"`
						CPUAbsolute    float64 `json:"cpu_absolute"`
						DiskBytes      float64 `json:"disk_bytes"`
						NetworkRxBytes float64 `json:"network_rx_bytes"`
						NetworkTxBytes float64 `json:"network_tx_bytes"`
					} `json:"resources"`
				}{
					CurrentState: "running",
					Resources: struct {
						MemoryBytes    float64 `json:"memory_bytes"`
						CPUAbsolute    float64 `json:"cpu_absolute"`
						DiskBytes      float64 `json:"disk_bytes"`
						NetworkRxBytes float64 `json:"network_rx_bytes"`
						NetworkTxBytes float64 `json:"network_tx_bytes"`
					}{MemoryBytes: 512 * 1024 * 1024, CPUAbsolute: 12.3},
				},
			})
		case strings.HasPrefix(r.URL.Path, "/api/client"):
			resp := page{Object: "list"}
			resp.Data = append(resp.Data,
				struct {
					Object     string "json:\"object\""
					Attributes struct {
						Identifier string "json:\"identifier\""
						Name       string "json:\"name\""
					} "json:\"attributes\""
				}{Object: "server", Attributes: struct {
					Identifier string "json:\"identifier\""
					Name       string "json:\"name\""
				}{Identifier: "abc123", Name: "mc-lobby"}},
				struct {
					Object     string "json:\"object\""
					Attributes struct {
						Identifier string "json:\"identifier\""
						Name       string "json:\"name\""
					} "json:\"attributes\""
				}{Object: "server", Attributes: struct {
					Identifier string "json:\"identifier\""
					Name       string "json:\"name\""
				}{Identifier: "def456", Name: "mc-prod"}},
				struct {
					Object     string "json:\"object\""
					Attributes struct {
						Identifier string "json:\"identifier\""
						Name       string "json:\"name\""
					} "json:\"attributes\""
				}{Object: "server", Attributes: struct {
					Identifier string "json:\"identifier\""
					Name       string "json:\"name\""
				}{Identifier: "ghi789", Name: "valheim"}},
			)
			resp.Meta.Pagination.CurrentPage = 1
			resp.Meta.Pagination.TotalPages = 1
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config.Store(&Config{DiscordToken: "x", PteroBaseURL: srv.URL, PteroClientToken: "y"})
	token := "y"

	got, err := listServers(token)
	if err != nil {
		t.Fatalf("listServers: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("listServers len=%d want 3", len(got))
	}

	id, err := resolveServerIDByName("valheim", token)
	if err != nil || id != "ghi789" {
		t.Fatalf("resolve exact -> (%s,%v)", id, err)
	}
	id, err = resolveServerIDByName("mc-", token)
	if err == nil {
		t.Fatalf("expected ambiguous error for prefix 'mc-', got id=%s", id)
	}
	id, err = resolveServerIDByName("val", token)
	if err != nil || id != "ghi789" {
		t.Fatalf("resolve prefix -> (%s,%v)", id, err)
	}

	stats, err := getResources("abc123", token)
	if err != nil {
		t.Fatalf("getResources: %v", err)
	}
	if stats.Attributes.CurrentState != "running" || stats.Attributes.Resources.CPUAbsolute <= 0 {
		t.Fatalf("unexpected resources: %+v", stats.Attributes)
	}
}

func TestListServers_EmptyToken(t *testing.T) {
	config.Store(&Config{PteroBaseURL: "https://example.com"})
	if _, err := listServers(""); err == nil || !strings.Contains(err.Error(), "missing API token") {
		t.Fatalf("expected missing token error, got %v", err)
	}
}

func TestResolveServerIDByName_EmptyInput(t *testing.T) {
	if _, err := resolveServerIDByName("", "tok"); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected required error, got %v", err)
	}
}

func TestResolveServerIDByName_NoMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := serverListResp{}
		resp.Meta.Pagination.CurrentPage = 1
		resp.Meta.Pagination.TotalPages = 1
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()
	config.Store(&Config{PteroBaseURL: srv.URL})

	if _, err := resolveServerIDByName("nonexistent", "tok"); err == nil || !strings.Contains(err.Error(), "no server matched") {
		t.Fatalf("expected no-match error, got %v", err)
	}
}

func TestCheckPanelHealth_DefaultTokenMissingOrPlaceholder(t *testing.T) {
	config.Store(&Config{PteroBaseURL: "https://example.invalid", PteroClientToken: ""})
	if err := checkPanelHealth(); err == nil || !strings.Contains(err.Error(), "default API key not set") {
		t.Fatalf("expected default missing error, got %v", err)
	}
	config.Store(&Config{PteroBaseURL: "https://example.invalid", PteroClientToken: "REPLACE_ME_PTERO_TOKEN"})
	if err := checkPanelHealth(); err == nil || !strings.Contains(err.Error(), "default API key not set") {
		t.Fatalf("expected default placeholder error, got %v", err)
	}
}

func TestCheckPanelHealth_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/client/account" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok": true}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	config.Store(&Config{PteroBaseURL: srv.URL, PteroClientToken: "valid"})
	if err := checkPanelHealth(); err != nil {
		t.Fatalf("checkPanelHealth ok -> %v", err)
	}
}

func TestCheckPanelHealth_Unhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"down"}`))
	}))
	defer srv.Close()
	config.Store(&Config{PteroBaseURL: srv.URL, PteroClientToken: "tok"})
	if err := checkPanelHealth(); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("expected 503 health error, got %v", err)
	}
}

func TestPostPower(t *testing.T) {
	var gotSignal, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/power") && r.Method == http.MethodPost {
			gotAuth = r.Header.Get("Authorization")
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			gotSignal = body["signal"]
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	config.Store(&Config{PteroBaseURL: srv.URL})

	if err := postPower("abc123", "restart", "mytoken"); err != nil {
		t.Fatalf("postPower: %v", err)
	}
	if gotSignal != "restart" {
		t.Fatalf("signal=%q want restart", gotSignal)
	}
	if gotAuth != "Bearer mytoken" {
		t.Fatalf("auth header=%q want 'Bearer mytoken'", gotAuth)
	}
}

func TestPostPower_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"Forbidden"}`))
	}))
	defer srv.Close()
	config.Store(&Config{PteroBaseURL: srv.URL})

	if err := postPower("id", "start", "bad-tok"); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403 error, got %v", err)
	}
}

func TestPostCommand(t *testing.T) {
	var gotCmd string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/command") && r.Method == http.MethodPost {
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			gotCmd = body["command"]
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	config.Store(&Config{PteroBaseURL: srv.URL})

	if err := postCommand("abc123", "say hello world", "tok"); err != nil {
		t.Fatalf("postCommand: %v", err)
	}
	if gotCmd != "say hello world" {
		t.Fatalf("command=%q want 'say hello world'", gotCmd)
	}
}

func TestPostCommand_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"Unauthorized"}`))
	}))
	defer srv.Close()
	config.Store(&Config{PteroBaseURL: srv.URL})

	if err := postCommand("id", "cmd", "bad-tok"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401 error, got %v", err)
	}
}

func TestPostBackup(t *testing.T) {
	var gotPath, gotMethod, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		if strings.HasSuffix(r.URL.Path, "/backups") && r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			gotBody = string(b)
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"object":"backup","attributes":{}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	config.Store(&Config{PteroBaseURL: srv.URL, PteroClientToken: "t"})
	ignored := "*.log\ncache/*"
	if err := postBackup("abc123", "my-backup", ignored, true, "t"); err != nil {
		t.Fatalf("postBackup: %v", err)
	}
	if !strings.HasSuffix(gotPath, "/api/client/servers/abc123/backups") || gotMethod != http.MethodPost {
		t.Fatalf("unexpected request path/method: %s %s", gotMethod, gotPath)
	}
	if !strings.Contains(gotBody, `"name":"my-backup"`) || !strings.Contains(gotBody, `"ignored":`) || !strings.Contains(gotBody, `is_locked":true`) {
		t.Fatalf("unexpected body: %s", gotBody)
	}
}

func TestPostBackup_MinimalFields(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	config.Store(&Config{PteroBaseURL: srv.URL})

	// No label, no ignored, no lock -> body should be {}
	if err := postBackup("srv1", "", "", false, "tok"); err != nil {
		t.Fatalf("postBackup minimal: %v", err)
	}
	if strings.Contains(gotBody, "name") || strings.Contains(gotBody, "ignored") || strings.Contains(gotBody, "locked") {
		t.Fatalf("minimal backup body should be empty object, got: %s", gotBody)
	}
}

// ---------- pagination test ----------

func TestListServers_Pagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		resp := serverListResp{}
		switch page {
		case "1", "":
			resp.Data = append(resp.Data, struct {
				Object     string `json:"object"`
				Attributes struct {
					Identifier string `json:"identifier"`
					Name       string `json:"name"`
				} `json:"attributes"`
			}{Attributes: struct {
				Identifier string `json:"identifier"`
				Name       string `json:"name"`
			}{Identifier: "p1", Name: "server-page1"}})
			resp.Meta.Pagination.CurrentPage = 1
			resp.Meta.Pagination.TotalPages = 2
		case "2":
			resp.Data = append(resp.Data, struct {
				Object     string `json:"object"`
				Attributes struct {
					Identifier string `json:"identifier"`
					Name       string `json:"name"`
				} `json:"attributes"`
			}{Attributes: struct {
				Identifier string `json:"identifier"`
				Name       string `json:"name"`
			}{Identifier: "p2", Name: "server-page2"}})
			resp.Meta.Pagination.CurrentPage = 2
			resp.Meta.Pagination.TotalPages = 2
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()
	config.Store(&Config{PteroBaseURL: srv.URL})

	servers, err := listServers("tok")
	if err != nil {
		t.Fatalf("listServers pagination: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers across pages, got %d", len(servers))
	}
}
