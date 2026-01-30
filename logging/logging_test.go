package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Dorico-Dynamics/txova-go-types/ids"

	txcontext "github.com/Dorico-Dynamics/txova-go-core/context"
)

func TestMaskPhone(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty", "", ""},
		{"full mozambique format", "+258841234567", "+258****4567"},
		{"with spaces", "+258 84 123 4567", "+258****4567"},
		{"with dashes", "+258-84-123-4567", "+258****4567"},
		{"without plus", "258841234567", "2588****4567"},
		{"local format", "841234567", "8****4567"},
		{"too short", "12345", "12345"},
		{"prefix 82", "+258821234567", "+258****4567"},
		{"prefix 83", "+258831234567", "+258****4567"},
		{"prefix 84", "+258841234567", "+258****4567"},
		{"prefix 85", "+258851234567", "+258****4567"},
		{"prefix 86", "+258861234567", "+258****4567"},
		{"prefix 87", "+258871234567", "+258****4567"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := MaskPhone(tt.input); got != tt.expected {
				t.Errorf("MaskPhone(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestMaskEmail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty", "", ""},
		{"standard email", "test@example.com", "t***@example.com"},
		{"long local part", "longusername@example.com", "l***@example.com"},
		{"single char local", "a@example.com", "a***@example.com"},
		{"subdomain", "user@mail.example.com", "u***@mail.example.com"},
		{"no at sign", "notanemail", "notanemail"},
		{"multiple at signs", "user@domain@example.com", "u***@domain@example.com"},
		{"numbers in local", "user123@example.com", "u***@example.com"},
		{"dots in local", "first.last@example.com", "f***@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := MaskEmail(tt.input); got != tt.expected {
				t.Errorf("MaskEmail(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestIsSensitiveField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		field    string
		expected bool
	}{
		{"password", "password", true},
		{"Password uppercase", "Password", true},
		{"PASSWORD all caps", "PASSWORD", true},
		{"token", "token", true},
		{"access_token", "access_token", true},
		{"refresh_token", "refresh_token", true},
		{"api_key", "api_key", true},
		{"apikey", "apikey", true},
		{"secret", "secret", true},
		{"authorization", "authorization", true},
		{"auth", "auth", true},
		{"credential", "credential", true},
		{"credentials", "credentials", true},
		{"private_key", "private_key", true},
		{"privatekey", "privatekey", true},
		{"username", "username", false},
		{"email", "email", false},
		{"user_id", "user_id", false},
		{"request_id", "request_id", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsSensitiveField(tt.field); got != tt.expected {
				t.Errorf("IsSensitiveField(%q) = %v, want %v", tt.field, got, tt.expected)
			}
		})
	}
}

func TestMaskSensitive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty", "", ""},
		{"secret value", "super-secret-password", "[REDACTED]"},
		{"token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "[REDACTED]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := MaskSensitive(tt.input); got != tt.expected {
				t.Errorf("MaskSensitive(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	if cfg.Level != slog.LevelInfo {
		t.Errorf("Level = %v, want %v", cfg.Level, slog.LevelInfo)
	}
	if cfg.Format != FormatText {
		t.Errorf("Format = %v, want %v", cfg.Format, FormatText)
	}
	if cfg.ServiceName != "txova" {
		t.Errorf("ServiceName = %v, want txova", cfg.ServiceName)
	}
}

func TestProductionConfig(t *testing.T) {
	t.Parallel()

	cfg := ProductionConfig("my-service")

	if cfg.Level != slog.LevelInfo {
		t.Errorf("Level = %v, want %v", cfg.Level, slog.LevelInfo)
	}
	if cfg.Format != FormatJSON {
		t.Errorf("Format = %v, want %v", cfg.Format, FormatJSON)
	}
	if cfg.ServiceName != "my-service" {
		t.Errorf("ServiceName = %v, want my-service", cfg.ServiceName)
	}
}

func TestLoggerJSON(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cfg := Config{
		Level:       slog.LevelDebug,
		Format:      FormatJSON,
		Output:      &buf,
		ServiceName: "test-service",
	}
	logger := New(cfg)

	logger.Info("test message", "key", "value")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse JSON log: %v", err)
	}

	if entry["msg"] != "test message" {
		t.Errorf("msg = %v, want 'test message'", entry["msg"])
	}
	if entry["key"] != "value" {
		t.Errorf("key = %v, want 'value'", entry["key"])
	}
	if entry["service"] != "test-service" {
		t.Errorf("service = %v, want 'test-service'", entry["service"])
	}
	if entry["level"] != "INFO" {
		t.Errorf("level = %v, want 'INFO'", entry["level"])
	}
}

func TestLoggerText(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cfg := Config{
		Level:       slog.LevelDebug,
		Format:      FormatText,
		Output:      &buf,
		ServiceName: "test-service",
	}
	logger := New(cfg)

	logger.Info("test message", "key", "value")

	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Errorf("output should contain 'test message', got: %s", output)
	}
	if !strings.Contains(output, "key=value") {
		t.Errorf("output should contain 'key=value', got: %s", output)
	}
	if !strings.Contains(output, "service=test-service") {
		t.Errorf("output should contain 'service=test-service', got: %s", output)
	}
}

func TestLoggerLevels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		logFunc   func(*Logger)
		level     string
		shouldLog bool
	}{
		{"debug at debug level", func(l *Logger) { l.Debug("msg") }, "DEBUG", true},
		{"info at debug level", func(l *Logger) { l.Info("msg") }, "INFO", true},
		{"warn at debug level", func(l *Logger) { l.Warn("msg") }, "WARN", true},
		{"error at debug level", func(l *Logger) { l.Error("msg") }, "ERROR", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			logger := New(Config{
				Level:  slog.LevelDebug,
				Format: FormatJSON,
				Output: &buf,
			})

			tt.logFunc(logger)

			if tt.shouldLog && buf.Len() == 0 {
				t.Error("expected log output but got none")
			}

			if tt.shouldLog {
				var entry map[string]any
				if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
					t.Fatalf("failed to parse JSON: %v", err)
				}
				if entry["level"] != tt.level {
					t.Errorf("level = %v, want %v", entry["level"], tt.level)
				}
			}
		})
	}
}

func TestLoggerLevelFiltering(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(Config{
		Level:  slog.LevelWarn,
		Format: FormatJSON,
		Output: &buf,
	})

	logger.Debug("debug message")
	logger.Info("info message")

	if buf.Len() > 0 {
		t.Error("debug and info messages should be filtered at warn level")
	}

	logger.Warn("warn message")
	if buf.Len() == 0 {
		t.Error("warn message should be logged at warn level")
	}
}

func TestLoggerWithContext(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(Config{
		Level:  slog.LevelDebug,
		Format: FormatJSON,
		Output: &buf,
	})

	ctx := context.Background()
	ctx = txcontext.WithRequestID(ctx, "req-123")
	testUserID := ids.MustNewUserID()
	ctx = txcontext.WithClaims(ctx, &txcontext.UserClaims{UserID: testUserID})
	ctx = txcontext.WithCorrelationID(ctx, "corr-789")

	logger.InfoContext(ctx, "test message")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if entry["request_id"] != "req-123" {
		t.Errorf("request_id = %v, want 'req-123'", entry["request_id"])
	}
	if entry["user_id"] != testUserID.String() {
		t.Errorf("user_id = %v, want '%s'", entry["user_id"], testUserID.String())
	}
	if entry["correlation_id"] != "corr-789" {
		t.Errorf("correlation_id = %v, want 'corr-789'", entry["correlation_id"])
	}
}

func TestLoggerWithContextEmpty(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(Config{
		Level:  slog.LevelDebug,
		Format: FormatJSON,
		Output: &buf,
	})

	ctx := context.Background()
	logger.InfoContext(ctx, "test message")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if _, ok := entry["request_id"]; ok {
		t.Error("request_id should not be present when not set in context")
	}
	if _, ok := entry["user_id"]; ok {
		t.Error("user_id should not be present when not set in context")
	}
}

func TestLoggerWith(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(Config{
		Level:  slog.LevelDebug,
		Format: FormatJSON,
		Output: &buf,
	})

	childLogger := logger.With("component", "auth")
	childLogger.Info("test message")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if entry["component"] != "auth" {
		t.Errorf("component = %v, want 'auth'", entry["component"])
	}
}

func TestLoggerContextMethods(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ctx = txcontext.WithRequestID(ctx, "req-test")

	tests := []struct {
		name    string
		logFunc func(*Logger, context.Context)
		level   string
	}{
		{"DebugContext", func(l *Logger, c context.Context) { l.DebugContext(c, "msg") }, "DEBUG"},
		{"InfoContext", func(l *Logger, c context.Context) { l.InfoContext(c, "msg") }, "INFO"},
		{"WarnContext", func(l *Logger, c context.Context) { l.WarnContext(c, "msg") }, "WARN"},
		{"ErrorContext", func(l *Logger, c context.Context) { l.ErrorContext(c, "msg") }, "ERROR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			logger := New(Config{
				Level:  slog.LevelDebug,
				Format: FormatJSON,
				Output: &buf,
			})

			tt.logFunc(logger, ctx)

			var entry map[string]any
			if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
				t.Fatalf("failed to parse JSON: %v", err)
			}

			if entry["level"] != tt.level {
				t.Errorf("level = %v, want %v", entry["level"], tt.level)
			}
			if entry["request_id"] != "req-test" {
				t.Errorf("request_id = %v, want 'req-test'", entry["request_id"])
			}
		})
	}
}

func TestSafeAttr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		key      string
		value    string
		expected string
	}{
		{"non-sensitive", "username", "john", "john"},
		{"password", "password", "secret123", "[REDACTED]"},
		{"token", "token", "abc123", "[REDACTED]"},
		{"api_key", "api_key", "key123", "[REDACTED]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			attr := SafeAttr(tt.key, tt.value)
			if attr.Value.String() != tt.expected {
				t.Errorf("SafeAttr(%q, %q) value = %q, want %q", tt.key, tt.value, attr.Value.String(), tt.expected)
			}
		})
	}
}

func TestPhoneAttr(t *testing.T) {
	t.Parallel()

	attr := PhoneAttr("phone", "+258841234567")
	if attr.Key != "phone" {
		t.Errorf("key = %v, want 'phone'", attr.Key)
	}
	if attr.Value.String() != "+258****4567" {
		t.Errorf("value = %v, want '+258****4567'", attr.Value.String())
	}
}

func TestEmailAttr(t *testing.T) {
	t.Parallel()

	attr := EmailAttr("email", "test@example.com")
	if attr.Key != "email" {
		t.Errorf("key = %v, want 'email'", attr.Key)
	}
	if attr.Value.String() != "t***@example.com" {
		t.Errorf("value = %v, want 't***@example.com'", attr.Value.String())
	}
}

func TestDurationAttr(t *testing.T) {
	t.Parallel()

	attr := DurationAttr("duration_ms", 1500*time.Millisecond)
	if attr.Key != "duration_ms" {
		t.Errorf("key = %v, want 'duration_ms'", attr.Key)
	}
	if attr.Value.Int64() != 1500 {
		t.Errorf("value = %v, want 1500", attr.Value.Int64())
	}
}

func TestErrorAttr(t *testing.T) {
	t.Parallel()

	t.Run("with error", func(t *testing.T) {
		t.Parallel()
		err := errors.New("something went wrong")
		attr := ErrorAttr(err)
		if attr.Key != "error" {
			t.Errorf("key = %v, want 'error'", attr.Key)
		}
		if attr.Value.String() != "something went wrong" {
			t.Errorf("value = %v, want 'something went wrong'", attr.Value.String())
		}
	})

	t.Run("nil error", func(t *testing.T) {
		t.Parallel()
		attr := ErrorAttr(nil)
		if attr.Key != "" {
			t.Errorf("key should be empty for nil error, got %v", attr.Key)
		}
	})
}

func TestLoggerSlog(t *testing.T) {
	t.Parallel()

	logger := New(DefaultConfig())
	slogLogger := logger.Slog()

	if slogLogger == nil {
		t.Error("Slog() should not return nil")
	}
}

func TestDefaultLogger(t *testing.T) {
	// Not parallel - modifies global state.

	// Save original.
	original := defaultLogger
	defer func() { defaultLogger = original }()

	// Get the default logger.
	logger := Default()
	if logger == nil {
		t.Error("Default() should not return nil")
	}

	// Create a custom logger and set it as default.
	var buf bytes.Buffer
	customLogger := New(Config{
		Level:       slog.LevelDebug,
		Format:      FormatJSON,
		Output:      &buf,
		ServiceName: "custom",
	})

	SetDefault(customLogger)
	if Default() != customLogger {
		t.Error("Default() should return the custom logger after SetDefault")
	}

	// Test package-level functions.
	Info("test info")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if entry["service"] != "custom" {
		t.Errorf("service = %v, want 'custom'", entry["service"])
	}
}

func TestPackageLevelFunctions(t *testing.T) {
	// Not parallel - modifies global state.

	var buf bytes.Buffer
	customLogger := New(Config{
		Level:       slog.LevelDebug,
		Format:      FormatJSON,
		Output:      &buf,
		ServiceName: "test",
	})

	// Save and restore original default.
	original := defaultLogger
	defer func() { defaultLogger = original }()

	SetDefault(customLogger)

	tests := []struct {
		name    string
		logFunc func()
		level   string
	}{
		{"Debug", func() { Debug("debug msg") }, "DEBUG"},
		{"Info", func() { buf.Reset(); Info("info msg") }, "INFO"},
		{"Warn", func() { buf.Reset(); Warn("warn msg") }, "WARN"},
		{"Error", func() { buf.Reset(); Error("error msg") }, "ERROR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			tt.logFunc()

			var entry map[string]any
			if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
				t.Fatalf("failed to parse JSON: %v", err)
			}

			if entry["level"] != tt.level {
				t.Errorf("level = %v, want %v", entry["level"], tt.level)
			}
		})
	}
}

func TestLoggerNilOutput(t *testing.T) {
	t.Parallel()

	// Should default to os.Stdout when Output is nil.
	cfg := Config{
		Level:  slog.LevelInfo,
		Format: FormatText,
		Output: nil,
	}

	logger := New(cfg)
	if logger == nil {
		t.Error("New should not return nil when Output is nil")
	}
}

func TestLoggerEmptyServiceName(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(Config{
		Level:       slog.LevelDebug,
		Format:      FormatJSON,
		Output:      &buf,
		ServiceName: "",
	})

	logger.Info("test message")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if _, ok := entry["service"]; ok {
		t.Error("service field should not be present when ServiceName is empty")
	}
}

func TestTimeFormatISO8601(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(Config{
		Level:  slog.LevelDebug,
		Format: FormatJSON,
		Output: &buf,
	})

	logger.Info("test message")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	timeStr, ok := entry["time"].(string)
	if !ok {
		t.Fatal("time field should be a string")
	}

	// Verify it's in RFC3339 format.
	if _, err := time.Parse(time.RFC3339, timeStr); err != nil {
		t.Errorf("time should be in RFC3339 format, got: %s", timeStr)
	}
}
