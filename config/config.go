// Package config provides configuration management for the Txova platform.
// It supports YAML file loading, environment variable overrides, validation,
// and secrets handling.
package config

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const tagValueTrue = "true"

// Config represents the complete application configuration.
type Config struct {
	Server        ServerConfig        `yaml:"server"`
	Database      DatabaseConfig      `yaml:"database"`
	Redis         RedisConfig         `yaml:"redis"`
	Kafka         KafkaConfig         `yaml:"kafka"`
	Auth          AuthConfig          `yaml:"auth"`
	Logging       LoggingConfig       `yaml:"logging"`
	Observability ObservabilityConfig `yaml:"observability"`
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	Host            string        `yaml:"host" env:"TXOVA_SERVER_HOST" default:"0.0.0.0"`
	Port            int           `yaml:"port" env:"TXOVA_SERVER_PORT" default:"8080"`
	ReadTimeout     time.Duration `yaml:"read_timeout" env:"TXOVA_SERVER_READ_TIMEOUT" default:"30s"`
	WriteTimeout    time.Duration `yaml:"write_timeout" env:"TXOVA_SERVER_WRITE_TIMEOUT" default:"30s"`
	RequestTimeout  time.Duration `yaml:"request_timeout" env:"TXOVA_SERVER_REQUEST_TIMEOUT" default:"30s"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" env:"TXOVA_SERVER_SHUTDOWN_TIMEOUT" default:"30s"`
}

// Address returns the server address in host:port format.
func (s ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

// DatabaseConfig holds database connection configuration.
type DatabaseConfig struct {
	Host           string `yaml:"host" env:"TXOVA_DATABASE_HOST" required:"true"`
	Port           int    `yaml:"port" env:"TXOVA_DATABASE_PORT" default:"5432"`
	Name           string `yaml:"name" env:"TXOVA_DATABASE_NAME" required:"true"`
	User           string `yaml:"user" env:"TXOVA_DATABASE_USER" required:"true"`
	Password       string `yaml:"password" env:"TXOVA_DATABASE_PASSWORD" required:"true" sensitive:"true"`
	MaxConnections int    `yaml:"max_connections" env:"TXOVA_DATABASE_MAX_CONNECTIONS" default:"25"`
	SSLMode        string `yaml:"ssl_mode" env:"TXOVA_DATABASE_SSL_MODE" default:"require"`
}

// DSN returns the PostgreSQL connection string.
func (d *DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.Name, d.SSLMode,
	)
}

// RedisConfig holds Redis connection configuration.
type RedisConfig struct {
	Host     string `yaml:"host" env:"TXOVA_REDIS_HOST" default:"localhost"`
	Port     int    `yaml:"port" env:"TXOVA_REDIS_PORT" default:"6379"`
	Password string `yaml:"password" env:"TXOVA_REDIS_PASSWORD" sensitive:"true"`
	DB       int    `yaml:"db" env:"TXOVA_REDIS_DB" default:"0"`
	PoolSize int    `yaml:"pool_size" env:"TXOVA_REDIS_POOL_SIZE" default:"10"`
}

// Address returns the Redis address in host:port format.
func (r RedisConfig) Address() string {
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}

// KafkaConfig holds Kafka connection configuration.
type KafkaConfig struct {
	Brokers  []string `yaml:"brokers" env:"TXOVA_KAFKA_BROKERS"`
	GroupID  string   `yaml:"group_id" env:"TXOVA_KAFKA_GROUP_ID"`
	ClientID string   `yaml:"client_id" env:"TXOVA_KAFKA_CLIENT_ID"`
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	JWTSecret     string        `yaml:"jwt_secret" env:"TXOVA_AUTH_JWT_SECRET" required:"true" sensitive:"true"`
	JWTIssuer     string        `yaml:"jwt_issuer" env:"TXOVA_AUTH_JWT_ISSUER" default:"txova"`
	TokenExpiry   time.Duration `yaml:"token_expiry" env:"TXOVA_AUTH_TOKEN_EXPIRY" default:"24h"`
	RefreshExpiry time.Duration `yaml:"refresh_expiry" env:"TXOVA_AUTH_REFRESH_EXPIRY" default:"720h"`
}

// LoggingConfig holds logging configuration.
type LoggingConfig struct {
	Level  string `yaml:"level" env:"TXOVA_LOGGING_LEVEL" default:"info"`
	Format string `yaml:"format" env:"TXOVA_LOGGING_FORMAT" default:"json"`
	Output string `yaml:"output" env:"TXOVA_LOGGING_OUTPUT" default:"stdout"`
}

// ObservabilityConfig holds observability configuration.
type ObservabilityConfig struct {
	MetricsPort     int    `yaml:"metrics_port" env:"TXOVA_OBSERVABILITY_METRICS_PORT" default:"9090"`
	TracingEndpoint string `yaml:"tracing_endpoint" env:"TXOVA_OBSERVABILITY_TRACING_ENDPOINT"`
	ServiceName     string `yaml:"service_name" env:"TXOVA_OBSERVABILITY_SERVICE_NAME" default:"txova"`
}

// Load loads configuration from a YAML file with environment variable overrides.
// Environment variables take precedence over YAML values.
// Returns an error if required fields are missing or validation fails.
func Load(path string) (*Config, error) {
	cfg := &Config{}

	// Apply defaults first.
	if err := applyDefaults(cfg); err != nil {
		return nil, fmt.Errorf("applying defaults: %w", err)
	}

	// Load from YAML file if provided and exists.
	if path != "" {
		data, err := os.ReadFile(path) // #nosec G304 -- path is intentionally configurable for config file loading
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("reading config file: %w", err)
			}
			// File doesn't exist, continue with defaults and env vars.
		} else {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("parsing config file: %w", err)
			}
		}
	}

	// Apply environment variable overrides.
	if err := applyEnvOverrides(cfg); err != nil {
		return nil, fmt.Errorf("applying env overrides: %w", err)
	}

	// Resolve secret references.
	if err := resolveSecrets(cfg); err != nil {
		return nil, fmt.Errorf("resolving secrets: %w", err)
	}

	// Validate required fields.
	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	return cfg, nil
}

// LoadFromEnv loads configuration purely from environment variables.
// This is useful for containerized environments.
func LoadFromEnv() (*Config, error) {
	return Load("")
}

// applyDefaults sets default values for all fields with a default tag.
func applyDefaults(cfg *Config) error {
	return applyDefaultsToValue(reflect.ValueOf(cfg).Elem())
}

func applyDefaultsToValue(v reflect.Value) error {
	t := v.Type()

	for i := range t.NumField() {
		field := t.Field(i)
		fieldValue := v.Field(i)

		// Recurse into nested structs.
		if field.Type.Kind() == reflect.Struct && field.Type != reflect.TypeOf(time.Time{}) {
			if err := applyDefaultsToValue(fieldValue); err != nil {
				return err
			}
			continue
		}

		// Get default tag.
		defaultVal := field.Tag.Get("default")
		if defaultVal == "" {
			continue
		}

		// Only apply default if field is zero value.
		if !fieldValue.IsZero() {
			continue
		}

		if err := setFieldValue(fieldValue, defaultVal); err != nil {
			return fmt.Errorf("setting default for %s: %w", field.Name, err)
		}
	}

	return nil
}

// applyEnvOverrides applies environment variable overrides to the config.
func applyEnvOverrides(cfg *Config) error {
	return applyEnvOverridesToValue(reflect.ValueOf(cfg).Elem())
}

func applyEnvOverridesToValue(v reflect.Value) error {
	t := v.Type()

	for i := range t.NumField() {
		field := t.Field(i)
		fieldValue := v.Field(i)

		// Recurse into nested structs.
		if field.Type.Kind() == reflect.Struct && field.Type != reflect.TypeOf(time.Time{}) {
			if err := applyEnvOverridesToValue(fieldValue); err != nil {
				return err
			}
			continue
		}

		// Get env tag.
		envVar := field.Tag.Get("env")
		if envVar == "" {
			continue
		}

		// Check if environment variable is set.
		envVal := os.Getenv(envVar)
		if envVal == "" {
			continue
		}

		if err := setFieldValue(fieldValue, envVal); err != nil {
			return fmt.Errorf("setting env var %s: %w", envVar, err)
		}
	}

	return nil
}

// setFieldValue sets a reflect.Value from a string.
func setFieldValue(v reflect.Value, s string) error {
	switch v.Kind() {
	case reflect.String:
		v.SetString(s)
	case reflect.Int, reflect.Int64:
		// Check if it's a time.Duration.
		if v.Type() == reflect.TypeOf(time.Duration(0)) {
			d, err := time.ParseDuration(s)
			if err != nil {
				return fmt.Errorf("parsing duration %q: %w", s, err)
			}
			v.SetInt(int64(d))
		} else {
			i, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return fmt.Errorf("parsing int %q: %w", s, err)
			}
			v.SetInt(i)
		}
	case reflect.Bool:
		b, err := strconv.ParseBool(s)
		if err != nil {
			return fmt.Errorf("parsing bool %q: %w", s, err)
		}
		v.SetBool(b)
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.String {
			// Split comma-separated values.
			parts := strings.Split(s, ",")
			for i, p := range parts {
				parts[i] = strings.TrimSpace(p)
			}
			v.Set(reflect.ValueOf(parts))
		}
	default:
		return fmt.Errorf("unsupported type: %v", v.Kind())
	}
	return nil
}

// resolveSecrets resolves secret references in the config.
// Supports formats:
//   - ${env:VAR_NAME} - reads from environment variable.
//   - ${vault:path/to/secret:key} - placeholder for vault integration.
func resolveSecrets(cfg *Config) error {
	return resolveSecretsInValue(reflect.ValueOf(cfg).Elem())
}

func resolveSecretsInValue(v reflect.Value) error {
	t := v.Type()

	for i := range t.NumField() {
		field := t.Field(i)
		fieldValue := v.Field(i)

		// Recurse into nested structs.
		if field.Type.Kind() == reflect.Struct && field.Type != reflect.TypeOf(time.Time{}) {
			if err := resolveSecretsInValue(fieldValue); err != nil {
				return err
			}
			continue
		}

		// Only process string fields.
		if field.Type.Kind() != reflect.String {
			continue
		}

		s := fieldValue.String()
		resolved, err := resolveSecretReference(s)
		if err != nil {
			return fmt.Errorf("resolving secret for %s: %w", field.Name, err)
		}
		fieldValue.SetString(resolved)
	}

	return nil
}

// resolveSecretReference resolves a single secret reference.
func resolveSecretReference(s string) (string, error) {
	if !strings.HasPrefix(s, "${") || !strings.HasSuffix(s, "}") {
		return s, nil
	}

	inner := s[2 : len(s)-1]

	// Handle ${env:VAR_NAME} format.
	if strings.HasPrefix(inner, "env:") {
		envVar := strings.TrimPrefix(inner, "env:")
		value := os.Getenv(envVar)
		if value == "" {
			return "", fmt.Errorf("environment variable %s not set", envVar)
		}
		return value, nil
	}

	// Handle ${vault:path:key} format - placeholder for future vault integration.
	if strings.HasPrefix(inner, "vault:") {
		return "", fmt.Errorf("vault secrets not yet implemented: %s", s)
	}

	return s, nil
}

// validate checks that all required fields are set.
func validate(cfg *Config) error {
	var missing []string
	validateValue(reflect.ValueOf(cfg).Elem(), "", &missing)

	if len(missing) > 0 {
		return fmt.Errorf("missing required fields: %s", strings.Join(missing, ", "))
	}

	return nil
}

func validateValue(v reflect.Value, prefix string, missing *[]string) {
	t := v.Type()

	for i := range t.NumField() {
		field := t.Field(i)
		fieldValue := v.Field(i)

		fieldName := field.Name
		if prefix != "" {
			fieldName = prefix + "." + fieldName
		}

		// Recurse into nested structs.
		if field.Type.Kind() == reflect.Struct && field.Type != reflect.TypeOf(time.Time{}) {
			validateValue(fieldValue, fieldName, missing)
			continue
		}

		// Check required tag.
		if field.Tag.Get("required") == tagValueTrue {
			if isZero(fieldValue) {
				*missing = append(*missing, fieldName)
			}
		}
	}
}

// isZero checks if a value is its zero value.
func isZero(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		return v.String() == ""
	case reflect.Int, reflect.Int64:
		return v.Int() == 0
	case reflect.Slice:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	default:
		return v.IsZero()
	}
}

// IsSensitive checks if a field is marked as sensitive.
func IsSensitive(fieldName string) bool {
	cfg := &Config{}
	return isSensitiveField(reflect.TypeOf(*cfg), fieldName)
}

func isSensitiveField(t reflect.Type, fieldPath string) bool {
	parts := strings.Split(fieldPath, ".")

	for i, part := range parts {
		field, ok := t.FieldByName(part)
		if !ok {
			return false
		}

		if i == len(parts)-1 {
			return field.Tag.Get("sensitive") == tagValueTrue
		}

		if field.Type.Kind() == reflect.Struct {
			t = field.Type
		} else {
			return false
		}
	}

	return false
}

// SensitiveFields returns a list of all sensitive field paths.
func SensitiveFields() []string {
	var fields []string
	collectSensitiveFields(reflect.TypeOf(Config{}), "", &fields)
	return fields
}

func collectSensitiveFields(t reflect.Type, prefix string, fields *[]string) {
	for i := range t.NumField() {
		field := t.Field(i)

		fieldName := field.Name
		if prefix != "" {
			fieldName = prefix + "." + fieldName
		}

		if field.Type.Kind() == reflect.Struct && field.Type != reflect.TypeOf(time.Time{}) {
			collectSensitiveFields(field.Type, fieldName, fields)
			continue
		}

		if field.Tag.Get("sensitive") == tagValueTrue {
			*fields = append(*fields, fieldName)
		}
	}
}
