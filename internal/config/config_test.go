package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func clearEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"HTTP_ADDR", "DATABASE_URL", "DATABASE_URL_FILE", "API_KEY", "API_KEY_FILE", "TLS_CERT_FILE", "TLS_KEY_FILE", "RATE_LIMIT_RPS", "RATE_LIMIT_BURST"} {
		t.Setenv(name, "")
	}
}

const testDatabaseURL = "postgres://test:test@localhost/test"

func TestLoad(t *testing.T) {
	for _, tt := range []struct {
		name      string
		values    map[string]string
		wantError string
		want      *Config
	}{
		{"defaults", nil, "", &Config{HTTPAddr: DefaultHTTPAddr, DatabaseURL: testDatabaseURL, RateRPS: DefaultRateRPS, RateBurst: DefaultRateBurst}},
		{"missing database", map[string]string{"DATABASE_URL": ""}, "required", nil},
		{"bad address", map[string]string{"HTTP_ADDR": "localhost"}, "host:port", nil},
		{"bad port", map[string]string{"HTTP_ADDR": ":99999"}, "port", nil},
		{"short key", map[string]string{"API_KEY": "short"}, "32 bytes", nil},
		{"blank key", map[string]string{"API_KEY": strings.Repeat(" ", 32)}, "empty", nil},
		{"blank database", map[string]string{"DATABASE_URL": " \t "}, "empty", nil},
		{"newline inside key", map[string]string{"API_KEY": strings.Repeat("a", 32) + "\n" + strings.Repeat("b", 32)}, "printable ASCII", nil},
		{"delete character in key", map[string]string{"API_KEY": strings.Repeat("a", 32) + "\x7f"}, "printable ASCII", nil},
		{"non-ASCII key", map[string]string{"API_KEY": strings.Repeat("я", 16)}, "printable ASCII", nil},
		{"inner space and tab in key", map[string]string{"API_KEY": strings.Repeat("a", 16) + " \t" + strings.Repeat("b", 16)}, "", nil},
		{"partial certificate", map[string]string{"TLS_CERT_FILE": "cert.pem"}, "together", nil},
		{"partial key", map[string]string{"TLS_KEY_FILE": "key.pem"}, "together", nil},
		{"bad rate", map[string]string{"RATE_LIMIT_RPS": "bad"}, "positive", nil},
		{"zero rate", map[string]string{"RATE_LIMIT_RPS": "0"}, "positive", nil},
		{"nan rate", map[string]string{"RATE_LIMIT_RPS": "NaN"}, "positive", nil},
		{"infinite rate", map[string]string{"RATE_LIMIT_RPS": "+Inf"}, "positive", nil},
		{"zero burst", map[string]string{"RATE_LIMIT_BURST": "0"}, "positive", nil},
		{"bad burst", map[string]string{"RATE_LIMIT_BURST": "bad"}, "positive", nil},
		{"both database sources", map[string]string{"DATABASE_URL_FILE": "db.txt"}, "only one", nil},
		{"both key sources", map[string]string{"API_KEY": "this-key-is-long-enough-for-validation", "API_KEY_FILE": "key.txt"}, "only one", nil},
		{"unreadable secret", map[string]string{"API_KEY_FILE": filepath.Join(t.TempDir(), "missing")}, "cannot read", nil},
		{"configured", map[string]string{"HTTP_ADDR": ":9090", "API_KEY": "this-key-is-long-enough-for-validation", "TLS_CERT_FILE": "cert.pem", "TLS_KEY_FILE": "key.pem", "RATE_LIMIT_RPS": "5.5", "RATE_LIMIT_BURST": "10"}, "", &Config{HTTPAddr: ":9090", DatabaseURL: testDatabaseURL, APIKey: "this-key-is-long-enough-for-validation", TLSCertFile: "cert.pem", TLSKeyFile: "key.pem", RateRPS: 5.5, RateBurst: 10}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clearEnvironment(t)
			t.Setenv("DATABASE_URL", testDatabaseURL)
			for name, value := range tt.values {
				t.Setenv(name, value)
			}
			cfg, err := Load()
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("got %v, want %q", err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.want != nil && cfg != *tt.want {
				t.Fatalf("got %+v, want %+v", cfg, *tt.want)
			}
		})
	}
}

func TestInvalidUTF8Environment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows stores the environment as UTF-16, so invalid bytes are replaced before Load reads them")
	}
	clearEnvironment(t)
	t.Setenv("DATABASE_URL", testDatabaseURL)
	t.Setenv("API_KEY", strings.Repeat("a", 32)+string([]byte{0xff}))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("expected invalid encoding failure, got %v", err)
	}
}

func TestKeyFileHeaderSafety(t *testing.T) {
	clearEnvironment(t)
	t.Setenv("DATABASE_URL", testDatabaseURL)
	file := filepath.Join(t.TempDir(), "key")
	key := strings.Repeat("a", 32) + "\r\n" + strings.Repeat("b", 32)
	if err := os.WriteFile(file, []byte(key+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("API_KEY_FILE", file)
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "API_KEY_FILE must contain only printable ASCII") {
		t.Fatalf("expected header safety failure, got %v", err)
	}
	if strings.Contains(err.Error(), "aaaa") || strings.Contains(err.Error(), "bbbb") {
		t.Fatal("error message leaked the key")
	}
}

func TestSecretFiles(t *testing.T) {
	clearEnvironment(t)
	dir := t.TempDir()
	databaseFile := filepath.Join(dir, "database")
	keyFile := filepath.Join(dir, "key")
	for path, value := range map[string]string{databaseFile: "postgres://test:test@localhost/test\n", keyFile: "this-key-is-long-enough-for-validation\n"} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("DATABASE_URL_FILE", databaseFile)
	t.Setenv("API_KEY_FILE", keyFile)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(cfg.APIKey, "\n") || cfg.DatabaseURL != "postgres://test:test@localhost/test" {
		t.Fatal("secret newline was not trimmed")
	}
	if err := os.WriteFile(keyFile, []byte("\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected empty secret failure, got %v", err)
	}
	if err := os.WriteFile(keyFile, []byte{0xff}, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("expected invalid encoding failure, got %v", err)
	}
}

func TestSecretSourcesNormalizeEqually(t *testing.T) {
	clearEnvironment(t)
	key := strings.Repeat("a", 32)
	t.Setenv("API_KEY", " \t"+key+"\n")
	fromEnv, _, err := secret("API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(file, []byte(" \t"+key+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("API_KEY", "")
	t.Setenv("API_KEY_FILE", file)
	fromFile, _, err := secret("API_KEY")
	if err != nil || fromFile != key || fromEnv != fromFile {
		t.Fatalf("secret sources differ: %v", err)
	}
}
