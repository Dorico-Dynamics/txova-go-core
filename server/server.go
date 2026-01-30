// Package server provides HTTP server setup with Chi router, middleware chain,
// and standardized JSON responses for the Txova platform.
package server

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Dorico-Dynamics/txova-go-core/config"
	"github.com/Dorico-Dynamics/txova-go-core/logging"
)

// Server represents an HTTP server with configured middleware and routing.
type Server struct {
	router  *chi.Mux
	config  Config
	logger  *logging.Logger
	httpSrv *http.Server
}

// Config holds server configuration.
type Config struct {
	// Host is the address to bind to.
	Host string
	// Port is the port to listen on.
	Port int
	// ReadTimeout is the maximum duration for reading the entire request.
	ReadTimeout time.Duration
	// WriteTimeout is the maximum duration before timing out writes of the response.
	WriteTimeout time.Duration
	// RequestTimeout is the timeout for individual requests.
	RequestTimeout time.Duration
	// ShutdownTimeout is the maximum duration to wait for active connections to close.
	ShutdownTimeout time.Duration
	// CORSConfig holds CORS configuration.
	CORSConfig *CORSConfig
}

// CORSConfig holds CORS configuration.
type CORSConfig struct {
	// AllowedOrigins is a list of origins that may access the resource.
	AllowedOrigins []string
	// AllowedMethods is a list of methods the client is allowed to use.
	AllowedMethods []string
	// AllowedHeaders is a list of headers the client is allowed to use.
	AllowedHeaders []string
	// ExposedHeaders is a list of headers that are safe to expose.
	ExposedHeaders []string
	// AllowCredentials indicates whether the request can include user credentials.
	AllowCredentials bool
	// MaxAge indicates how long the results of a preflight request can be cached.
	MaxAge int
}

// DefaultConfig returns a default server configuration.
func DefaultConfig() Config {
	return Config{
		Host:            "0.0.0.0",
		Port:            8080,
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		RequestTimeout:  30 * time.Second,
		ShutdownTimeout: 30 * time.Second,
		CORSConfig: &CORSConfig{
			AllowedOrigins:   []string{"*"},
			AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID", "X-Correlation-ID"},
			ExposedHeaders:   []string{"X-Request-ID"},
			AllowCredentials: false,
			MaxAge:           86400,
		},
	}
}

// ConfigFromAppConfig creates a server config from the application config.
func ConfigFromAppConfig(cfg config.ServerConfig) Config {
	return Config{
		Host:            cfg.Host,
		Port:            cfg.Port,
		ReadTimeout:     cfg.ReadTimeout,
		WriteTimeout:    cfg.WriteTimeout,
		RequestTimeout:  cfg.ReadTimeout,
		ShutdownTimeout: cfg.ShutdownTimeout,
		CORSConfig:      DefaultConfig().CORSConfig,
	}
}

// New creates a new server with the given configuration and logger.
func New(cfg Config, logger *logging.Logger) *Server {
	if logger == nil {
		logger = logging.New(logging.DefaultConfig())
	}

	router := chi.NewRouter()

	s := &Server{
		router: router,
		config: cfg,
		logger: logger,
	}

	// Apply middleware in the correct order.
	s.setupMiddleware()

	return s
}

// setupMiddleware configures the standard middleware chain.
// Order matters:
//  1. Request ID injection.
//  2. Panic recovery.
//  3. Structured logging.
//  4. Timeout.
//  5. CORS.
func (s *Server) setupMiddleware() {
	s.router.Use(s.requestIDMiddleware)
	s.router.Use(s.recoveryMiddleware)
	s.router.Use(s.loggingMiddleware)
	s.router.Use(s.timeoutMiddleware)
	if s.config.CORSConfig != nil {
		s.router.Use(s.corsMiddleware)
	}
}

// Router returns the underlying Chi router for route registration.
func (s *Server) Router() *chi.Mux {
	return s.router
}

// Address returns the server address.
func (s *Server) Address() string {
	return s.config.Host + ":" + itoa(s.config.Port)
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	s.httpSrv = &http.Server{
		Addr:         s.Address(),
		Handler:      s.router,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
	}

	s.logger.Info("server starting", "address", s.Address())
	return s.httpSrv.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpSrv == nil {
		return nil
	}

	s.logger.Info("server shutting down")

	shutdownCtx, cancel := context.WithTimeout(ctx, s.config.ShutdownTimeout)
	defer cancel()

	return s.httpSrv.Shutdown(shutdownCtx)
}

// itoa converts an int to a string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + itoa(-n)
	}
	var b [20]byte
	i := len(b) - 1
	for n > 0 {
		b[i] = byte('0' + n%10)
		n /= 10
		i--
	}
	return string(b[i+1:])
}
