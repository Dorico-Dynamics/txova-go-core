// Package logging provides structured logging for the Txova platform using
// the standard library slog package. It includes PII masking, context field
// extraction, and configurable output formats.
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"

	txcontext "github.com/Dorico-Dynamics/txova-go-core/context"
)

// Format represents the log output format.
type Format string

const (
	// FormatJSON outputs logs as JSON (for production).
	FormatJSON Format = "json"
	// FormatText outputs logs as human-readable text (for development).
	FormatText Format = "text"
)

// Config holds the configuration for the logger.
type Config struct {
	// Level is the minimum log level to output.
	Level slog.Level
	// Format is the output format (json or text).
	Format Format
	// Output is the writer to output logs to. Defaults to os.Stdout.
	Output io.Writer
	// ServiceName is the name of the service for the "service" field.
	ServiceName string
	// AddSource adds source code location to log entries.
	AddSource bool
}

// DefaultConfig returns a default configuration suitable for development.
func DefaultConfig() Config {
	return Config{
		Level:       slog.LevelInfo,
		Format:      FormatText,
		Output:      os.Stdout,
		ServiceName: "txova",
		AddSource:   false,
	}
}

// ProductionConfig returns a configuration suitable for production.
func ProductionConfig(serviceName string) Config {
	return Config{
		Level:       slog.LevelInfo,
		Format:      FormatJSON,
		Output:      os.Stdout,
		ServiceName: serviceName,
		AddSource:   false,
	}
}

// Logger wraps slog.Logger with additional functionality for the Txova platform.
type Logger struct {
	logger      *slog.Logger
	serviceName string
}

// New creates a new Logger with the given configuration.
func New(cfg Config) *Logger {
	if cfg.Output == nil {
		cfg.Output = os.Stdout
	}

	var handler slog.Handler

	opts := &slog.HandlerOptions{
		Level:     cfg.Level,
		AddSource: cfg.AddSource,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Replace time format to ISO8601.
			if a.Key == slog.TimeKey {
				if t, ok := a.Value.Any().(time.Time); ok {
					return slog.String(slog.TimeKey, t.Format(time.RFC3339))
				}
			}
			return a
		},
	}

	switch cfg.Format {
	case FormatJSON:
		handler = slog.NewJSONHandler(cfg.Output, opts)
	default:
		handler = slog.NewTextHandler(cfg.Output, opts)
	}

	return &Logger{
		logger:      slog.New(handler),
		serviceName: cfg.ServiceName,
	}
}

// With returns a new Logger with the given attributes added.
func (l *Logger) With(args ...any) *Logger {
	return &Logger{
		logger:      l.logger.With(args...),
		serviceName: l.serviceName,
	}
}

// WithContext returns a new Logger with context fields extracted (request_id, user_id).
func (l *Logger) WithContext(ctx context.Context) *Logger {
	attrs := []any{}

	if requestID := txcontext.RequestID(ctx); requestID != "" {
		attrs = append(attrs, "request_id", requestID)
	}
	if userID := txcontext.UserID(ctx); !userID.IsZero() {
		attrs = append(attrs, "user_id", userID.String())
	}
	if correlationID := txcontext.CorrelationID(ctx); correlationID != "" {
		attrs = append(attrs, "correlation_id", correlationID)
	}

	if len(attrs) == 0 {
		return l
	}

	return l.With(attrs...)
}

// baseAttrs returns the base attributes for all log entries.
func (l *Logger) baseAttrs() []any {
	if l.serviceName != "" {
		return []any{"service", l.serviceName}
	}
	return nil
}

// Debug logs a message at debug level.
func (l *Logger) Debug(msg string, args ...any) {
	l.logger.Debug(msg, append(l.baseAttrs(), args...)...)
}

// Info logs a message at info level.
func (l *Logger) Info(msg string, args ...any) {
	l.logger.Info(msg, append(l.baseAttrs(), args...)...)
}

// Warn logs a message at warn level.
func (l *Logger) Warn(msg string, args ...any) {
	l.logger.Warn(msg, append(l.baseAttrs(), args...)...)
}

// Error logs a message at error level.
func (l *Logger) Error(msg string, args ...any) {
	l.logger.Error(msg, append(l.baseAttrs(), args...)...)
}

// DebugContext logs a message at debug level with context fields.
func (l *Logger) DebugContext(ctx context.Context, msg string, args ...any) {
	l.WithContext(ctx).Debug(msg, args...)
}

// InfoContext logs a message at info level with context fields.
func (l *Logger) InfoContext(ctx context.Context, msg string, args ...any) {
	l.WithContext(ctx).Info(msg, args...)
}

// WarnContext logs a message at warn level with context fields.
func (l *Logger) WarnContext(ctx context.Context, msg string, args ...any) {
	l.WithContext(ctx).Warn(msg, args...)
}

// ErrorContext logs a message at error level with context fields.
func (l *Logger) ErrorContext(ctx context.Context, msg string, args ...any) {
	l.WithContext(ctx).Error(msg, args...)
}

// Slog returns the underlying slog.Logger for advanced usage.
func (l *Logger) Slog() *slog.Logger {
	return l.logger
}

// PII masking functions.

// phoneRegex matches Mozambique phone numbers in various formats.
var phoneRegex = regexp.MustCompile(`(\+258|258)?[- ]?(8[2-7])[- ]?(\d{3})[- ]?(\d{4})`)

// MaskPhone masks a phone number for logging.
// Example: +258841234567 -> +258****4567
func MaskPhone(phone string) string {
	if phone == "" {
		return ""
	}

	// Normalize the phone number first.
	normalized := normalizePhone(phone)
	if len(normalized) < 9 {
		return phone // Return as-is if too short to mask properly.
	}

	// For normalized numbers like +258841234567, show +258****4567.
	if strings.HasPrefix(normalized, "+258") && len(normalized) == 13 {
		return normalized[:4] + "****" + normalized[len(normalized)-4:]
	}

	// For other formats, mask the middle part.
	if len(normalized) >= 9 {
		return normalized[:len(normalized)-8] + "****" + normalized[len(normalized)-4:]
	}

	return phone
}

// normalizePhone removes spaces and dashes from phone numbers.
func normalizePhone(phone string) string {
	result := strings.ReplaceAll(phone, " ", "")
	result = strings.ReplaceAll(result, "-", "")
	return result
}

// emailRegex matches email addresses.
var emailRegex = regexp.MustCompile(`^([^@]+)@(.+)$`)

// MaskEmail masks an email address for logging.
// Example: test@example.com -> t***@example.com
func MaskEmail(email string) string {
	if email == "" {
		return ""
	}

	matches := emailRegex.FindStringSubmatch(email)
	if len(matches) != 3 {
		return email // Return as-is if not a valid email format.
	}

	localPart := matches[1]
	domain := matches[2]

	if len(localPart) == 0 {
		return email
	}

	// Show first character and mask the rest.
	maskedLocal := string(localPart[0]) + "***"
	return maskedLocal + "@" + domain
}

// Sensitive field detection for automatic masking.

// sensitiveFields contains field names that should be masked in logs.
var sensitiveFields = map[string]bool{
	"password":      true,
	"token":         true,
	"access_token":  true,
	"refresh_token": true,
	"api_key":       true,
	"apikey":        true,
	"secret":        true,
	"authorization": true,
	"auth":          true,
	"credential":    true,
	"credentials":   true,
	"private_key":   true,
	"privatekey":    true,
}

// IsSensitiveField checks if a field name is sensitive and should be masked.
func IsSensitiveField(name string) bool {
	return sensitiveFields[strings.ToLower(name)]
}

// MaskSensitive returns a masked value for sensitive fields.
func MaskSensitive(value string) string {
	if value == "" {
		return ""
	}
	return "[REDACTED]"
}

// SafeAttr creates a slog attribute, automatically masking sensitive fields.
func SafeAttr(key string, value string) slog.Attr {
	if IsSensitiveField(key) {
		return slog.String(key, MaskSensitive(value))
	}
	return slog.String(key, value)
}

// PhoneAttr creates a masked phone number attribute.
func PhoneAttr(key string, phone string) slog.Attr {
	return slog.String(key, MaskPhone(phone))
}

// EmailAttr creates a masked email attribute.
func EmailAttr(key string, email string) slog.Attr {
	return slog.String(key, MaskEmail(email))
}

// DurationAttr creates a duration attribute in milliseconds.
func DurationAttr(key string, d time.Duration) slog.Attr {
	return slog.Int64(key, d.Milliseconds())
}

// ErrorAttr creates an error attribute.
func ErrorAttr(err error) slog.Attr {
	if err == nil {
		return slog.Attr{}
	}
	return slog.String("error", err.Error())
}

// Default logger for package-level functions.
var defaultLogger = New(DefaultConfig())

// SetDefault sets the default logger.
func SetDefault(l *Logger) {
	defaultLogger = l
}

// Default returns the default logger.
func Default() *Logger {
	return defaultLogger
}

// Package-level logging functions using the default logger.

// Debug logs a message at debug level using the default logger.
func Debug(msg string, args ...any) {
	defaultLogger.Debug(msg, args...)
}

// Info logs a message at info level using the default logger.
func Info(msg string, args ...any) {
	defaultLogger.Info(msg, args...)
}

// Warn logs a message at warn level using the default logger.
func Warn(msg string, args ...any) {
	defaultLogger.Warn(msg, args...)
}

// Error logs a message at error level using the default logger.
func Error(msg string, args ...any) {
	defaultLogger.Error(msg, args...)
}
