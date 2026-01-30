// Package app provides application lifecycle management for the Txova platform.
// It handles graceful startup with ordered dependency initialization, graceful
// shutdown with signal handling and connection draining, health endpoints, and
// panic recovery at the application level.
package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Dorico-Dynamics/txova-go-core/errors"
	"github.com/Dorico-Dynamics/txova-go-core/logging"
	"github.com/Dorico-Dynamics/txova-go-core/server"
)

// State represents the current state of the application.
type State int32

const (
	// StateCreated indicates the app has been created but not started.
	StateCreated State = iota
	// StateStarting indicates the app is starting up.
	StateStarting
	// StateRunning indicates the app is running and ready to serve requests.
	StateRunning
	// StateShuttingDown indicates the app is shutting down.
	StateShuttingDown
	// StateStopped indicates the app has stopped.
	StateStopped
)

// String returns the string representation of the state.
func (s State) String() string {
	switch s {
	case StateCreated:
		return "created"
	case StateStarting:
		return "starting"
	case StateRunning:
		return "running"
	case StateShuttingDown:
		return "shutting_down"
	case StateStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

// Config holds application configuration.
type Config struct {
	// Name is the application name.
	Name string
	// Version is the application version.
	Version string
	// ShutdownTimeout is the maximum duration to wait for graceful shutdown.
	// Default: 30 seconds.
	ShutdownTimeout time.Duration
	// StartupTimeout is the maximum duration to wait for startup to complete.
	// Default: 30 seconds.
	StartupTimeout time.Duration
}

// DefaultConfig returns a default application configuration.
func DefaultConfig() Config {
	return Config{
		Name:            "txova",
		Version:         "1.0.0",
		ShutdownTimeout: 30 * time.Second,
		StartupTimeout:  30 * time.Second,
	}
}

// HealthChecker is an interface for components that can report their health.
type HealthChecker interface {
	// Name returns the name of the component.
	Name() string
	// Check returns nil if the component is healthy, or an error describing the issue.
	Check(ctx context.Context) error
}

// HealthCheckFunc is a function type that implements HealthChecker.
type HealthCheckFunc struct {
	name  string
	check func(ctx context.Context) error
}

// NewHealthCheck creates a new HealthChecker from a function.
func NewHealthCheck(name string, check func(ctx context.Context) error) HealthChecker {
	return &HealthCheckFunc{name: name, check: check}
}

// Name returns the name of the health check.
func (h *HealthCheckFunc) Name() string {
	return h.name
}

// Check executes the health check function.
func (h *HealthCheckFunc) Check(ctx context.Context) error {
	return h.check(ctx)
}

// Initializer is an interface for components that need initialization on startup.
type Initializer interface {
	// Name returns the name of the component.
	Name() string
	// Init initializes the component. Returns an error if initialization fails.
	Init(ctx context.Context) error
}

// InitFunc is a function type that implements Initializer.
type InitFunc struct {
	name string
	init func(ctx context.Context) error
}

// NewInitializer creates a new Initializer from a function.
func NewInitializer(name string, init func(ctx context.Context) error) Initializer {
	return &InitFunc{name: name, init: init}
}

// Name returns the name of the initializer.
func (i *InitFunc) Name() string {
	return i.name
}

// Init executes the initialization function.
func (i *InitFunc) Init(ctx context.Context) error {
	return i.init(ctx)
}

// Closer is an interface for components that need cleanup on shutdown.
type Closer interface {
	// Name returns the name of the component.
	Name() string
	// Close cleans up the component. Returns an error if cleanup fails.
	Close(ctx context.Context) error
}

// CloseFunc is a function type that implements Closer.
type CloseFunc struct {
	name  string
	close func(ctx context.Context) error
}

// NewCloser creates a new Closer from a function.
func NewCloser(name string, close func(ctx context.Context) error) Closer {
	return &CloseFunc{name: name, close: close}
}

// Name returns the name of the closer.
func (c *CloseFunc) Name() string {
	return c.name
}

// Close executes the close function.
func (c *CloseFunc) Close(ctx context.Context) error {
	return c.close(ctx)
}

// App represents the main application with lifecycle management.
type App struct {
	config       Config
	logger       *logging.Logger
	server       *server.Server
	state        atomic.Int32
	healthChecks []HealthChecker
	initializers []Initializer
	closers      []Closer
	mu           sync.RWMutex
	shutdownCh   chan struct{}
	doneCh       chan struct{}

	// signalNotify allows testing to inject a mock signal notifier.
	signalNotify func(c chan<- os.Signal, sig ...os.Signal)
}

// Option is a functional option for configuring an App.
type Option func(*App)

// WithLogger sets the logger for the application.
func WithLogger(logger *logging.Logger) Option {
	return func(a *App) {
		a.logger = logger
	}
}

// WithServer sets the HTTP server for the application.
func WithServer(srv *server.Server) Option {
	return func(a *App) {
		a.server = srv
	}
}

// WithHealthCheck adds a health checker to the application.
func WithHealthCheck(checker HealthChecker) Option {
	return func(a *App) {
		a.healthChecks = append(a.healthChecks, checker)
	}
}

// WithInitializer adds an initializer to the application.
func WithInitializer(init Initializer) Option {
	return func(a *App) {
		a.initializers = append(a.initializers, init)
	}
}

// WithCloser adds a closer to the application.
func WithCloser(closer Closer) Option {
	return func(a *App) {
		a.closers = append(a.closers, closer)
	}
}

// New creates a new App with the given configuration and options.
func New(cfg Config, opts ...Option) *App {
	a := &App{
		config:       cfg,
		shutdownCh:   make(chan struct{}),
		doneCh:       make(chan struct{}),
		signalNotify: signal.Notify,
	}
	a.state.Store(int32(StateCreated))

	for _, opt := range opts {
		opt(a)
	}

	if a.logger == nil {
		a.logger = logging.New(logging.DefaultConfig())
	}

	return a
}

// State returns the current state of the application.
func (a *App) State() State {
	return State(a.state.Load())
}

// IsReady returns true if the application is running and all health checks pass.
func (a *App) IsReady() bool {
	if a.State() != StateRunning {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, hc := range a.healthChecks {
		if err := hc.Check(ctx); err != nil {
			return false
		}
	}

	return true
}

// IsLive returns true if the application is not stopped.
func (a *App) IsLive() bool {
	state := a.State()
	return state != StateStopped
}

// RegisterHealthCheck registers a health checker.
func (a *App) RegisterHealthCheck(checker HealthChecker) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.healthChecks = append(a.healthChecks, checker)
}

// RegisterInitializer registers an initializer.
func (a *App) RegisterInitializer(init Initializer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.initializers = append(a.initializers, init)
}

// RegisterCloser registers a closer.
func (a *App) RegisterCloser(closer Closer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closers = append(a.closers, closer)
}

// Run starts the application and blocks until shutdown.
// It handles SIGTERM and SIGINT for graceful shutdown.
func (a *App) Run() error {
	if !a.state.CompareAndSwap(int32(StateCreated), int32(StateStarting)) {
		return errors.New(errors.CodeInternalError, "application already started")
	}

	// Set up signal handling.
	sigCh := make(chan os.Signal, 1)
	a.signalNotify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// Initialize dependencies.
	if err := a.initialize(); err != nil {
		a.state.Store(int32(StateStopped))
		return err
	}

	a.state.Store(int32(StateRunning))
	a.logger.Info("application started",
		"name", a.config.Name,
		"version", a.config.Version,
	)

	// Start the server if configured.
	var serverErr error
	if a.server != nil {
		go func() {
			if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				serverErr = err
				a.Shutdown()
			}
		}()
	}

	// Wait for shutdown signal or explicit shutdown.
	select {
	case sig := <-sigCh:
		a.logger.Info("received shutdown signal", "signal", sig.String())
	case <-a.shutdownCh:
		a.logger.Info("shutdown requested")
	}

	// Perform graceful shutdown.
	if err := a.shutdown(); err != nil {
		return err
	}

	if serverErr != nil {
		return errors.Wrap(errors.CodeInternalError, "server error", serverErr)
	}

	return nil
}

// Shutdown initiates graceful shutdown of the application.
func (a *App) Shutdown() {
	select {
	case <-a.shutdownCh:
		// Already shutting down.
	default:
		close(a.shutdownCh)
	}
}

// Done returns a channel that is closed when the application has stopped.
func (a *App) Done() <-chan struct{} {
	return a.doneCh
}

// initialize runs all initializers in order.
func (a *App) initialize() error {
	ctx, cancel := context.WithTimeout(context.Background(), a.config.StartupTimeout)
	defer cancel()

	a.mu.RLock()
	initializers := make([]Initializer, len(a.initializers))
	copy(initializers, a.initializers)
	a.mu.RUnlock()

	for _, init := range initializers {
		a.logger.Info("initializing component", "component", init.Name())

		if err := a.runWithRecovery(func() error {
			return init.Init(ctx)
		}); err != nil {
			a.logger.Error("initialization failed",
				"component", init.Name(),
				"error", err.Error(),
			)
			return errors.Wrap(errors.CodeInternalError,
				fmt.Sprintf("failed to initialize %s", init.Name()), err)
		}

		a.logger.Info("component initialized", "component", init.Name())
	}

	return nil
}

// shutdown performs graceful shutdown.
func (a *App) shutdown() error {
	if !a.state.CompareAndSwap(int32(StateRunning), int32(StateShuttingDown)) {
		// Already shutting down or not running.
		return nil
	}

	defer func() {
		a.state.Store(int32(StateStopped))
		close(a.doneCh)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), a.config.ShutdownTimeout)
	defer cancel()

	a.logger.Info("shutting down application", "timeout", a.config.ShutdownTimeout.String())

	// Shutdown server first to stop accepting new requests.
	if a.server != nil {
		if err := a.server.Shutdown(ctx); err != nil {
			a.logger.Error("server shutdown error", "error", err.Error())
		}
	}

	// Close dependencies in reverse order.
	a.mu.RLock()
	closers := make([]Closer, len(a.closers))
	copy(closers, a.closers)
	a.mu.RUnlock()

	var lastErr error
	for i := len(closers) - 1; i >= 0; i-- {
		closer := closers[i]
		a.logger.Info("closing component", "component", closer.Name())

		if err := a.runWithRecovery(func() error {
			return closer.Close(ctx)
		}); err != nil {
			a.logger.Error("close failed",
				"component", closer.Name(),
				"error", err.Error(),
			)
			lastErr = err
		} else {
			a.logger.Info("component closed", "component", closer.Name())
		}
	}

	a.logger.Info("application stopped")
	return lastErr
}

// runWithRecovery runs a function and recovers from panics.
func (a *App) runWithRecovery(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			a.logger.Error("panic recovered", "panic", fmt.Sprintf("%v", r))
			err = errors.InternalErrorf("panic: %v", r)
		}
	}()
	return fn()
}

// HealthStatus represents the health status of a component.
type HealthStatus struct {
	Name    string `json:"name"`
	Healthy bool   `json:"healthy"`
	Error   string `json:"error,omitempty"`
}

// HealthReport represents the overall health report.
type HealthReport struct {
	Status     string         `json:"status"`
	Components []HealthStatus `json:"components,omitempty"`
}

// CheckHealth runs all health checks and returns a report.
func (a *App) CheckHealth(ctx context.Context) HealthReport {
	a.mu.RLock()
	healthChecks := make([]HealthChecker, len(a.healthChecks))
	copy(healthChecks, a.healthChecks)
	a.mu.RUnlock()

	report := HealthReport{
		Status:     "healthy",
		Components: make([]HealthStatus, 0, len(healthChecks)),
	}

	for _, hc := range healthChecks {
		status := HealthStatus{
			Name:    hc.Name(),
			Healthy: true,
		}

		if err := hc.Check(ctx); err != nil {
			status.Healthy = false
			status.Error = err.Error()
			report.Status = "unhealthy"
		}

		report.Components = append(report.Components, status)
	}

	return report
}
