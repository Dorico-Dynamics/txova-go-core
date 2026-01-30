package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	txcontext "github.com/Dorico-Dynamics/txova-go-core/context"
	"github.com/Dorico-Dynamics/txova-go-core/logging"
)

// requestIDMiddleware injects a unique request ID into the context.
func (s *Server) requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for existing request ID in header.
		requestID := r.Header.Get(txcontext.HeaderRequestID)
		if requestID == "" {
			requestID = generateRequestID()
		}

		// Check for correlation ID.
		correlationID := r.Header.Get(txcontext.HeaderCorrelationID)

		// Set request ID in response header.
		w.Header().Set(txcontext.HeaderRequestID, requestID)

		// Add to context.
		ctx := txcontext.WithRequestID(r.Context(), requestID)
		if correlationID != "" {
			ctx = txcontext.WithCorrelationID(ctx, correlationID)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// recoveryMiddleware recovers from panics and returns a 500 error.
func (s *Server) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				// Log the panic with stack trace.
				s.logger.ErrorContext(r.Context(), "panic recovered",
					"panic", rec,
					"stack", string(debug.Stack()),
				)

				// Return generic error to client (never expose internal details).
				WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "an internal error occurred")
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs request details.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code.
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Process request.
		next.ServeHTTP(wrapped, r)

		// Log request completion.
		duration := time.Since(start)
		s.logger.InfoContext(r.Context(), "request completed",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.statusCode,
			logging.DurationAttr("duration_ms", duration),
			"remote_addr", getRemoteAddr(r),
		)
	})
}

// timeoutMiddleware adds a timeout to the request context.
// Note: This middleware only sets a deadline on the context. It's the handler's
// responsibility to check ctx.Done() for cancellation. For full request timeout
// behavior, use http.TimeoutHandler at the route level.
func (s *Server) timeoutMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), s.config.RequestTimeout)
		defer cancel()

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// corsMiddleware handles CORS headers.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := s.config.CORSConfig
		origin := r.Header.Get("Origin")

		// Check if origin is allowed.
		allowed := false
		for _, o := range cfg.AllowedOrigins {
			if o == "*" || o == origin {
				allowed = true
				break
			}
		}

		if allowed && origin != "" {
			if cfg.AllowedOrigins[0] == "*" {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}

			if cfg.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			if len(cfg.ExposedHeaders) > 0 {
				w.Header().Set("Access-Control-Expose-Headers", strings.Join(cfg.ExposedHeaders, ", "))
			}
		}

		// Handle preflight requests.
		if r.Method == http.MethodOptions {
			if len(cfg.AllowedMethods) > 0 {
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(cfg.AllowedMethods, ", "))
			}
			if len(cfg.AllowedHeaders) > 0 {
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(cfg.AllowedHeaders, ", "))
			}
			if cfg.MaxAge > 0 {
				w.Header().Set("Access-Control-Max-Age", itoa(cfg.MaxAge))
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

// WriteHeader captures the status code before writing.
func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.written = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

// Write implements the io.Writer interface.
func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.written = true
	}
	return rw.ResponseWriter.Write(b)
}

// generateRequestID generates a unique request ID.
func generateRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID if random fails.
		return "req-" + itoa(int(time.Now().UnixNano()))
	}
	return "req-" + hex.EncodeToString(b)
}

// getRemoteAddr extracts the client's IP address, considering proxies.
func getRemoteAddr(r *http.Request) string {
	// Check X-Forwarded-For header (from proxies/load balancers).
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list.
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header.
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr.
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// MetricsCollector is an interface for collecting HTTP request metrics.
// Implementations can use this to integrate with Prometheus, StatsD, or other
// metrics systems.
type MetricsCollector interface {
	// RecordRequest records metrics for a completed HTTP request.
	// method: HTTP method (GET, POST, etc.)
	// path: URL path (may be a pattern like /users/{id})
	// statusCode: HTTP response status code
	// duration: Time taken to handle the request
	RecordRequest(method, path string, statusCode int, duration time.Duration)

	// RecordPanic records when a panic occurs during request handling.
	RecordPanic(method, path string)
}

// metricsMiddleware collects request metrics using the provided collector.
func metricsMiddleware(collector MetricsCollector) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status code.
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Handle panics for metrics.
			defer func() {
				if rec := recover(); rec != nil {
					collector.RecordPanic(r.Method, r.URL.Path)
					panic(rec) // Re-panic to let recovery middleware handle it.
				}
			}()

			// Process request.
			next.ServeHTTP(wrapped, r)

			// Record metrics.
			collector.RecordRequest(r.Method, r.URL.Path, wrapped.statusCode, time.Since(start))
		})
	}
}

// WithMetrics adds metrics collection to the server middleware chain.
// The metrics middleware runs after the logging middleware.
func (s *Server) WithMetrics(collector MetricsCollector) {
	if collector == nil {
		return
	}
	s.router.Use(metricsMiddleware(collector))
}

// NoopMetricsCollector is a no-op implementation of MetricsCollector.
// Use this when metrics collection is not needed.
type NoopMetricsCollector struct{}

// RecordRequest does nothing.
func (NoopMetricsCollector) RecordRequest(method, path string, statusCode int, duration time.Duration) {
}

// RecordPanic does nothing.
func (NoopMetricsCollector) RecordPanic(method, path string) {}
