package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServerConfig_Address(t *testing.T) {
	t.Parallel()

	cfg := ServerConfig{
		Host: "localhost",
		Port: 8080,
	}

	if got := cfg.Address(); got != "localhost:8080" {
		t.Errorf("Address() = %v, want localhost:8080", got)
	}
}

func TestDatabaseConfig_DSN(t *testing.T) {
	t.Parallel()

	cfg := DatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		Name:     "txova",
		User:     "admin",
		Password: "secret",
		SSLMode:  "require",
	}

	expected := "host=localhost port=5432 user=admin password=secret dbname=txova sslmode=require"
	if got := cfg.DSN(); got != expected {
		t.Errorf("DSN() = %v, want %v", got, expected)
	}
}

func TestRedisConfig_Address(t *testing.T) {
	t.Parallel()

	cfg := RedisConfig{
		Host: "localhost",
		Port: 6379,
	}

	if got := cfg.Address(); got != "localhost:6379" {
		t.Errorf("Address() = %v, want localhost:6379", got)
	}
}

func TestLoad_Defaults(t *testing.T) {
	// Not parallel - uses t.Setenv.

	// Set required fields via env.
	t.Setenv("TXOVA_DATABASE_HOST", "testdb")
	t.Setenv("TXOVA_DATABASE_NAME", "testname")
	t.Setenv("TXOVA_DATABASE_USER", "testuser")
	t.Setenv("TXOVA_DATABASE_PASSWORD", "testpass")
	t.Setenv("TXOVA_AUTH_JWT_SECRET", "testsecret")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Check server defaults.
	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("Server.Host = %v, want 0.0.0.0", cfg.Server.Host)
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("Server.Port = %v, want 8080", cfg.Server.Port)
	}
	if cfg.Server.ReadTimeout != 30*time.Second {
		t.Errorf("Server.ReadTimeout = %v, want 30s", cfg.Server.ReadTimeout)
	}

	// Check database defaults.
	if cfg.Database.Port != 5432 {
		t.Errorf("Database.Port = %v, want 5432", cfg.Database.Port)
	}
	if cfg.Database.MaxConnections != 25 {
		t.Errorf("Database.MaxConnections = %v, want 25", cfg.Database.MaxConnections)
	}
	if cfg.Database.SSLMode != "require" {
		t.Errorf("Database.SSLMode = %v, want require", cfg.Database.SSLMode)
	}

	// Check Redis defaults.
	if cfg.Redis.Host != "localhost" {
		t.Errorf("Redis.Host = %v, want localhost", cfg.Redis.Host)
	}
	if cfg.Redis.Port != 6379 {
		t.Errorf("Redis.Port = %v, want 6379", cfg.Redis.Port)
	}
	if cfg.Redis.PoolSize != 10 {
		t.Errorf("Redis.PoolSize = %v, want 10", cfg.Redis.PoolSize)
	}

	// Check Auth defaults.
	if cfg.Auth.JWTIssuer != "txova" {
		t.Errorf("Auth.JWTIssuer = %v, want txova", cfg.Auth.JWTIssuer)
	}
	if cfg.Auth.TokenExpiry != 24*time.Hour {
		t.Errorf("Auth.TokenExpiry = %v, want 24h", cfg.Auth.TokenExpiry)
	}
	if cfg.Auth.RefreshExpiry != 720*time.Hour {
		t.Errorf("Auth.RefreshExpiry = %v, want 720h", cfg.Auth.RefreshExpiry)
	}

	// Check Logging defaults.
	if cfg.Logging.Level != "info" {
		t.Errorf("Logging.Level = %v, want info", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("Logging.Format = %v, want json", cfg.Logging.Format)
	}

	// Check Observability defaults.
	if cfg.Observability.MetricsPort != 9090 {
		t.Errorf("Observability.MetricsPort = %v, want 9090", cfg.Observability.MetricsPort)
	}
	if cfg.Observability.ServiceName != "txova" {
		t.Errorf("Observability.ServiceName = %v, want txova", cfg.Observability.ServiceName)
	}
}

func TestLoad_YAMLFile(t *testing.T) {
	t.Parallel()

	yamlContent := `
server:
  host: "127.0.0.1"
  port: 9000
  read_timeout: 60s
database:
  host: "db.example.com"
  port: 5433
  name: "mydb"
  user: "myuser"
  password: "mypassword"
  ssl_mode: "disable"
redis:
  host: "redis.example.com"
  port: 6380
auth:
  jwt_secret: "my-jwt-secret"
  jwt_issuer: "my-issuer"
  token_expiry: 12h
logging:
  level: "debug"
  format: "text"
`

	// Create temp file.
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("Server.Host = %v, want 127.0.0.1", cfg.Server.Host)
	}
	if cfg.Server.Port != 9000 {
		t.Errorf("Server.Port = %v, want 9000", cfg.Server.Port)
	}
	if cfg.Server.ReadTimeout != 60*time.Second {
		t.Errorf("Server.ReadTimeout = %v, want 60s", cfg.Server.ReadTimeout)
	}
	if cfg.Database.Host != "db.example.com" {
		t.Errorf("Database.Host = %v, want db.example.com", cfg.Database.Host)
	}
	if cfg.Database.Port != 5433 {
		t.Errorf("Database.Port = %v, want 5433", cfg.Database.Port)
	}
	if cfg.Database.SSLMode != "disable" {
		t.Errorf("Database.SSLMode = %v, want disable", cfg.Database.SSLMode)
	}
	if cfg.Auth.JWTIssuer != "my-issuer" {
		t.Errorf("Auth.JWTIssuer = %v, want my-issuer", cfg.Auth.JWTIssuer)
	}
	if cfg.Auth.TokenExpiry != 12*time.Hour {
		t.Errorf("Auth.TokenExpiry = %v, want 12h", cfg.Auth.TokenExpiry)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("Logging.Level = %v, want debug", cfg.Logging.Level)
	}
}

func TestLoad_EnvOverrides(t *testing.T) {
	// Not parallel - uses t.Setenv.

	yamlContent := `
server:
  host: "127.0.0.1"
  port: 8080
database:
  host: "db.example.com"
  name: "testdb"
  user: "testuser"
  password: "testpass"
auth:
  jwt_secret: "yaml-secret"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Set env vars that should override YAML.
	t.Setenv("TXOVA_SERVER_PORT", "9999")
	t.Setenv("TXOVA_DATABASE_HOST", "env-db.example.com")
	t.Setenv("TXOVA_AUTH_JWT_SECRET", "env-secret")

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Server host should be from YAML (no env override).
	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("Server.Host = %v, want 127.0.0.1", cfg.Server.Host)
	}
	// Server port should be from env.
	if cfg.Server.Port != 9999 {
		t.Errorf("Server.Port = %v, want 9999", cfg.Server.Port)
	}
	// Database host should be from env.
	if cfg.Database.Host != "env-db.example.com" {
		t.Errorf("Database.Host = %v, want env-db.example.com", cfg.Database.Host)
	}
	// Auth secret should be from env.
	if cfg.Auth.JWTSecret != "env-secret" {
		t.Errorf("Auth.JWTSecret = %v, want env-secret", cfg.Auth.JWTSecret)
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	t.Parallel()

	// Don't set any required fields.
	_, err := Load("")
	if err == nil {
		t.Error("Load() should fail when required fields are missing")
	}

	if err != nil && !contains(err.Error(), "missing required fields") {
		t.Errorf("error should mention missing required fields, got: %v", err)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("invalid: yaml: content:"), 0o600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Error("Load() should fail with invalid YAML")
	}
}

func TestLoad_NonExistentFile(t *testing.T) {
	// Not parallel - uses t.Setenv.

	// Set required fields via env.
	t.Setenv("TXOVA_DATABASE_HOST", "testdb")
	t.Setenv("TXOVA_DATABASE_NAME", "testname")
	t.Setenv("TXOVA_DATABASE_USER", "testuser")
	t.Setenv("TXOVA_DATABASE_PASSWORD", "testpass")
	t.Setenv("TXOVA_AUTH_JWT_SECRET", "testsecret")

	// Non-existent file should not cause error, just use defaults and env.
	cfg, err := Load("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("Server.Host = %v, want 0.0.0.0", cfg.Server.Host)
	}
}

func TestLoad_SecretReference_Env(t *testing.T) {
	// Not parallel - uses t.Setenv.

	yamlContent := `
database:
  host: "db.example.com"
  name: "testdb"
  user: "testuser"
  password: "${env:MY_DB_PASSWORD}"
auth:
  jwt_secret: "${env:MY_JWT_SECRET}"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Set the env vars that the secrets reference.
	t.Setenv("MY_DB_PASSWORD", "resolved-db-password")
	t.Setenv("MY_JWT_SECRET", "resolved-jwt-secret")

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Database.Password != "resolved-db-password" {
		t.Errorf("Database.Password = %v, want resolved-db-password", cfg.Database.Password)
	}
	if cfg.Auth.JWTSecret != "resolved-jwt-secret" {
		t.Errorf("Auth.JWTSecret = %v, want resolved-jwt-secret", cfg.Auth.JWTSecret)
	}
}

func TestLoad_SecretReference_EnvNotSet(t *testing.T) {
	t.Parallel()

	yamlContent := `
database:
  host: "db.example.com"
  name: "testdb"
  user: "testuser"
  password: "${env:NONEXISTENT_VAR}"
auth:
  jwt_secret: "direct-secret"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Error("Load() should fail when secret env var is not set")
	}

	if err != nil && !contains(err.Error(), "not set") {
		t.Errorf("error should mention env var not set, got: %v", err)
	}
}

func TestLoad_SecretReference_VaultNotImplemented(t *testing.T) {
	t.Parallel()

	yamlContent := `
database:
  host: "db.example.com"
  name: "testdb"
  user: "testuser"
  password: "${vault:secret/data/db:password}"
auth:
  jwt_secret: "direct-secret"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Error("Load() should fail for vault secrets (not implemented)")
	}

	if err != nil && !contains(err.Error(), "vault secrets not yet implemented") {
		t.Errorf("error should mention vault not implemented, got: %v", err)
	}
}

func TestLoadFromEnv(t *testing.T) {
	// Not parallel - uses t.Setenv.

	t.Setenv("TXOVA_SERVER_HOST", "env-host")
	t.Setenv("TXOVA_SERVER_PORT", "3000")
	t.Setenv("TXOVA_DATABASE_HOST", "env-db")
	t.Setenv("TXOVA_DATABASE_NAME", "envname")
	t.Setenv("TXOVA_DATABASE_USER", "envuser")
	t.Setenv("TXOVA_DATABASE_PASSWORD", "envpass")
	t.Setenv("TXOVA_AUTH_JWT_SECRET", "envsecret")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv() error = %v", err)
	}

	if cfg.Server.Host != "env-host" {
		t.Errorf("Server.Host = %v, want env-host", cfg.Server.Host)
	}
	if cfg.Server.Port != 3000 {
		t.Errorf("Server.Port = %v, want 3000", cfg.Server.Port)
	}
	if cfg.Database.Host != "env-db" {
		t.Errorf("Database.Host = %v, want env-db", cfg.Database.Host)
	}
}

func TestLoad_KafkaBrokers(t *testing.T) {
	// Not parallel - uses t.Setenv.

	t.Setenv("TXOVA_DATABASE_HOST", "testdb")
	t.Setenv("TXOVA_DATABASE_NAME", "testname")
	t.Setenv("TXOVA_DATABASE_USER", "testuser")
	t.Setenv("TXOVA_DATABASE_PASSWORD", "testpass")
	t.Setenv("TXOVA_AUTH_JWT_SECRET", "testsecret")
	t.Setenv("TXOVA_KAFKA_BROKERS", "broker1:9092, broker2:9092, broker3:9092")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(cfg.Kafka.Brokers) != 3 {
		t.Errorf("Kafka.Brokers length = %v, want 3", len(cfg.Kafka.Brokers))
	}
	if cfg.Kafka.Brokers[0] != "broker1:9092" {
		t.Errorf("Kafka.Brokers[0] = %v, want broker1:9092", cfg.Kafka.Brokers[0])
	}
	if cfg.Kafka.Brokers[2] != "broker3:9092" {
		t.Errorf("Kafka.Brokers[2] = %v, want broker3:9092", cfg.Kafka.Brokers[2])
	}
}

func TestIsSensitive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		field    string
		expected bool
	}{
		{"Database.Password", true},
		{"Redis.Password", true},
		{"Auth.JWTSecret", true},
		{"Database.Host", false},
		{"Server.Port", false},
		{"Auth.JWTIssuer", false},
		{"NonExistent.Field", false},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			t.Parallel()
			if got := IsSensitive(tt.field); got != tt.expected {
				t.Errorf("IsSensitive(%q) = %v, want %v", tt.field, got, tt.expected)
			}
		})
	}
}

func TestSensitiveFields(t *testing.T) {
	t.Parallel()

	fields := SensitiveFields()

	expectedFields := []string{"Database.Password", "Redis.Password", "Auth.JWTSecret"}
	for _, expected := range expectedFields {
		found := false
		for _, f := range fields {
			if f == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("SensitiveFields() should contain %q", expected)
		}
	}
}

func TestLoad_InvalidDuration(t *testing.T) {
	// Not parallel - uses t.Setenv.

	t.Setenv("TXOVA_DATABASE_HOST", "testdb")
	t.Setenv("TXOVA_DATABASE_NAME", "testname")
	t.Setenv("TXOVA_DATABASE_USER", "testuser")
	t.Setenv("TXOVA_DATABASE_PASSWORD", "testpass")
	t.Setenv("TXOVA_AUTH_JWT_SECRET", "testsecret")
	t.Setenv("TXOVA_SERVER_READ_TIMEOUT", "invalid")

	_, err := Load("")
	if err == nil {
		t.Error("Load() should fail with invalid duration")
	}
}

func TestLoad_InvalidInt(t *testing.T) {
	// Not parallel - uses t.Setenv.

	t.Setenv("TXOVA_DATABASE_HOST", "testdb")
	t.Setenv("TXOVA_DATABASE_NAME", "testname")
	t.Setenv("TXOVA_DATABASE_USER", "testuser")
	t.Setenv("TXOVA_DATABASE_PASSWORD", "testpass")
	t.Setenv("TXOVA_AUTH_JWT_SECRET", "testsecret")
	t.Setenv("TXOVA_SERVER_PORT", "not-a-number")

	_, err := Load("")
	if err == nil {
		t.Error("Load() should fail with invalid int")
	}
}

// contains is a helper to check if a string contains a substring.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || s != "" && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
