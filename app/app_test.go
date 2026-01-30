package app

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Dorico-Dynamics/txova-go-core/logging"
)

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	if cfg.Name != "txova" {
		t.Errorf("Name = %q, want %q", cfg.Name, "txova")
	}
	if cfg.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", cfg.Version, "1.0.0")
	}
	if cfg.ShutdownTimeout != 30*time.Second {
		t.Errorf("ShutdownTimeout = %v, want %v", cfg.ShutdownTimeout, 30*time.Second)
	}
	if cfg.StartupTimeout != 30*time.Second {
		t.Errorf("StartupTimeout = %v, want %v", cfg.StartupTimeout, 30*time.Second)
	}
}

func TestState_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state State
		want  string
	}{
		{StateCreated, "created"},
		{StateStarting, "starting"},
		{StateRunning, "running"},
		{StateShuttingDown, "shutting_down"},
		{StateStopped, "stopped"},
		{State(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.state.String(); got != tt.want {
				t.Errorf("State(%d).String() = %q, want %q", tt.state, got, tt.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Name:            "test-app",
		Version:         "2.0.0",
		ShutdownTimeout: 10 * time.Second,
		StartupTimeout:  5 * time.Second,
	}

	app := New(cfg)

	if app.config.Name != cfg.Name {
		t.Errorf("config.Name = %q, want %q", app.config.Name, cfg.Name)
	}
	if app.State() != StateCreated {
		t.Errorf("State() = %v, want %v", app.State(), StateCreated)
	}
	if app.logger == nil {
		t.Error("logger should not be nil")
	}
}

func TestNew_WithOptions(t *testing.T) {
	t.Parallel()

	logger := logging.New(logging.DefaultConfig())
	healthCheck := NewHealthCheck("test", func(ctx context.Context) error { return nil })
	initializer := NewInitializer("test", func(ctx context.Context) error { return nil })
	closer := NewCloser("test", func(ctx context.Context) error { return nil })

	app := New(
		DefaultConfig(),
		WithLogger(logger),
		WithHealthCheck(healthCheck),
		WithInitializer(initializer),
		WithCloser(closer),
	)

	if app.logger != logger {
		t.Error("logger not set correctly")
	}
	if len(app.healthChecks) != 1 {
		t.Errorf("len(healthChecks) = %d, want 1", len(app.healthChecks))
	}
	if len(app.initializers) != 1 {
		t.Errorf("len(initializers) = %d, want 1", len(app.initializers))
	}
	if len(app.closers) != 1 {
		t.Errorf("len(closers) = %d, want 1", len(app.closers))
	}
}

func TestApp_RegisterHealthCheck(t *testing.T) {
	t.Parallel()

	app := New(DefaultConfig())
	hc := NewHealthCheck("db", func(ctx context.Context) error { return nil })

	app.RegisterHealthCheck(hc)

	if len(app.healthChecks) != 1 {
		t.Errorf("len(healthChecks) = %d, want 1", len(app.healthChecks))
	}
	if app.healthChecks[0].Name() != "db" {
		t.Errorf("healthChecks[0].Name() = %q, want %q", app.healthChecks[0].Name(), "db")
	}
}

func TestApp_RegisterInitializer(t *testing.T) {
	t.Parallel()

	app := New(DefaultConfig())
	init := NewInitializer("cache", func(ctx context.Context) error { return nil })

	app.RegisterInitializer(init)

	if len(app.initializers) != 1 {
		t.Errorf("len(initializers) = %d, want 1", len(app.initializers))
	}
	if app.initializers[0].Name() != "cache" {
		t.Errorf("initializers[0].Name() = %q, want %q", app.initializers[0].Name(), "cache")
	}
}

func TestApp_RegisterCloser(t *testing.T) {
	t.Parallel()

	app := New(DefaultConfig())
	closer := NewCloser("db", func(ctx context.Context) error { return nil })

	app.RegisterCloser(closer)

	if len(app.closers) != 1 {
		t.Errorf("len(closers) = %d, want 1", len(app.closers))
	}
	if app.closers[0].Name() != "db" {
		t.Errorf("closers[0].Name() = %q, want %q", app.closers[0].Name(), "db")
	}
}

func TestApp_IsLive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		state State
		want  bool
	}{
		{"created", StateCreated, true},
		{"starting", StateStarting, true},
		{"running", StateRunning, true},
		{"shutting_down", StateShuttingDown, true},
		{"stopped", StateStopped, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			app := New(DefaultConfig())
			app.state.Store(int32(tt.state))

			if got := app.IsLive(); got != tt.want {
				t.Errorf("IsLive() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApp_IsReady(t *testing.T) {
	t.Parallel()

	t.Run("not running", func(t *testing.T) {
		t.Parallel()
		app := New(DefaultConfig())
		if app.IsReady() {
			t.Error("IsReady() should return false when not running")
		}
	})

	t.Run("running with passing health checks", func(t *testing.T) {
		t.Parallel()
		app := New(DefaultConfig())
		app.state.Store(int32(StateRunning))
		app.RegisterHealthCheck(NewHealthCheck("db", func(ctx context.Context) error {
			return nil
		}))

		if !app.IsReady() {
			t.Error("IsReady() should return true when running with passing health checks")
		}
	})

	t.Run("running with failing health check", func(t *testing.T) {
		t.Parallel()
		app := New(DefaultConfig())
		app.state.Store(int32(StateRunning))
		app.RegisterHealthCheck(NewHealthCheck("db", func(ctx context.Context) error {
			return errors.New("connection failed")
		}))

		if app.IsReady() {
			t.Error("IsReady() should return false when health check fails")
		}
	})
}

func TestApp_CheckHealth(t *testing.T) {
	t.Parallel()

	t.Run("no health checks", func(t *testing.T) {
		t.Parallel()
		app := New(DefaultConfig())
		report := app.CheckHealth(context.Background())

		if report.Status != "healthy" {
			t.Errorf("Status = %q, want %q", report.Status, "healthy")
		}
		if len(report.Components) != 0 {
			t.Errorf("len(Components) = %d, want 0", len(report.Components))
		}
	})

	t.Run("all healthy", func(t *testing.T) {
		t.Parallel()
		app := New(DefaultConfig())
		app.RegisterHealthCheck(NewHealthCheck("db", func(ctx context.Context) error { return nil }))
		app.RegisterHealthCheck(NewHealthCheck("cache", func(ctx context.Context) error { return nil }))

		report := app.CheckHealth(context.Background())

		if report.Status != "healthy" {
			t.Errorf("Status = %q, want %q", report.Status, "healthy")
		}
		if len(report.Components) != 2 {
			t.Errorf("len(Components) = %d, want 2", len(report.Components))
		}
		for _, c := range report.Components {
			if !c.Healthy {
				t.Errorf("Component %q should be healthy", c.Name)
			}
		}
	})

	t.Run("one unhealthy", func(t *testing.T) {
		t.Parallel()
		app := New(DefaultConfig())
		app.RegisterHealthCheck(NewHealthCheck("db", func(ctx context.Context) error { return nil }))
		app.RegisterHealthCheck(NewHealthCheck("cache", func(ctx context.Context) error {
			return errors.New("connection refused")
		}))

		report := app.CheckHealth(context.Background())

		if report.Status != "unhealthy" {
			t.Errorf("Status = %q, want %q", report.Status, "unhealthy")
		}

		var cacheStatus *HealthStatus
		for i, c := range report.Components {
			if c.Name == "cache" {
				cacheStatus = &report.Components[i]
				break
			}
		}
		if cacheStatus == nil {
			t.Fatal("cache component not found")
		}
		if cacheStatus.Healthy {
			t.Error("cache should be unhealthy")
		}
		if cacheStatus.Error != "connection refused" {
			t.Errorf("Error = %q, want %q", cacheStatus.Error, "connection refused")
		}
	})
}

func TestApp_Run_AlreadyStarted(t *testing.T) {
	t.Parallel()

	app := New(DefaultConfig())
	app.state.Store(int32(StateRunning))

	err := app.Run()
	if err == nil {
		t.Error("Run() should return error when already started")
	}
}

func TestApp_Run_InitializationFailure(t *testing.T) {
	t.Parallel()

	app := New(Config{
		Name:            "test",
		Version:         "1.0.0",
		ShutdownTimeout: 1 * time.Second,
		StartupTimeout:  1 * time.Second,
	})
	app.signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {}

	app.RegisterInitializer(NewInitializer("failing", func(ctx context.Context) error {
		return errors.New("init failed")
	}))

	err := app.Run()
	if err == nil {
		t.Error("Run() should return error when initialization fails")
	}
	if app.State() != StateStopped {
		t.Errorf("State() = %v, want %v", app.State(), StateStopped)
	}
}

func TestApp_Run_GracefulShutdown(t *testing.T) {
	t.Parallel()

	var initCalled, closeCalled bool
	var closeOrder []string
	var mu sync.Mutex

	app := New(Config{
		Name:            "test",
		Version:         "1.0.0",
		ShutdownTimeout: 5 * time.Second,
		StartupTimeout:  5 * time.Second,
	})

	// Mock signal notify to prevent actual signal handling.
	sigCh := make(chan os.Signal, 1)
	app.signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {
		go func() {
			for s := range sigCh {
				c <- s
			}
		}()
	}

	app.RegisterInitializer(NewInitializer("test-init", func(ctx context.Context) error {
		initCalled = true
		return nil
	}))

	app.RegisterCloser(NewCloser("closer1", func(ctx context.Context) error {
		mu.Lock()
		closeOrder = append(closeOrder, "closer1")
		mu.Unlock()
		closeCalled = true
		return nil
	}))

	app.RegisterCloser(NewCloser("closer2", func(ctx context.Context) error {
		mu.Lock()
		closeOrder = append(closeOrder, "closer2")
		mu.Unlock()
		return nil
	}))

	// Run in goroutine and trigger shutdown.
	done := make(chan error, 1)
	go func() {
		done <- app.Run()
	}()

	// Wait for app to start running.
	for i := 0; i < 100; i++ {
		if app.State() == StateRunning {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if app.State() != StateRunning {
		t.Fatal("app did not reach running state")
	}

	// Trigger shutdown.
	app.Shutdown()

	// Wait for completion.
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run() returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run() did not complete in time")
	}

	if !initCalled {
		t.Error("initializer was not called")
	}
	if !closeCalled {
		t.Error("closer was not called")
	}
	if app.State() != StateStopped {
		t.Errorf("State() = %v, want %v", app.State(), StateStopped)
	}

	// Verify closers were called in reverse order.
	mu.Lock()
	defer mu.Unlock()
	if len(closeOrder) != 2 {
		t.Errorf("len(closeOrder) = %d, want 2", len(closeOrder))
	} else {
		if closeOrder[0] != "closer2" || closeOrder[1] != "closer1" {
			t.Errorf("closeOrder = %v, want [closer2, closer1]", closeOrder)
		}
	}
}

func TestApp_Shutdown_Idempotent(t *testing.T) {
	t.Parallel()

	app := New(DefaultConfig())
	app.state.Store(int32(StateRunning))

	// Multiple calls should not panic.
	app.Shutdown()
	app.Shutdown()
	app.Shutdown()
}

func TestApp_Done(t *testing.T) {
	t.Parallel()

	app := New(DefaultConfig())
	app.signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {}

	done := make(chan struct{})
	go func() {
		<-app.Done()
		close(done)
	}()

	// Run the app and trigger shutdown.
	go func() {
		_ = app.Run()
	}()

	// Wait for running state.
	for i := 0; i < 100; i++ {
		if app.State() == StateRunning {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	app.Shutdown()

	select {
	case <-done:
		// Success.
	case <-time.After(5 * time.Second):
		t.Fatal("Done() channel was not closed")
	}
}

func TestApp_Run_PanicInInitializer(t *testing.T) {
	t.Parallel()

	app := New(Config{
		Name:            "test",
		Version:         "1.0.0",
		ShutdownTimeout: 1 * time.Second,
		StartupTimeout:  1 * time.Second,
	})
	app.signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {}

	app.RegisterInitializer(NewInitializer("panicking", func(ctx context.Context) error {
		panic("test panic")
	}))

	err := app.Run()
	if err == nil {
		t.Error("Run() should return error when initializer panics")
	}
}

func TestApp_Run_PanicInCloser(t *testing.T) {
	t.Parallel()

	app := New(Config{
		Name:            "test",
		Version:         "1.0.0",
		ShutdownTimeout: 1 * time.Second,
		StartupTimeout:  1 * time.Second,
	})
	app.signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {}

	app.RegisterCloser(NewCloser("panicking", func(ctx context.Context) error {
		panic("closer panic")
	}))

	// Run and trigger shutdown.
	done := make(chan error, 1)
	go func() {
		done <- app.Run()
	}()

	// Wait for running state.
	for i := 0; i < 100; i++ {
		if app.State() == StateRunning {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	app.Shutdown()

	select {
	case err := <-done:
		if err == nil {
			t.Error("Run() should return error when closer panics")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not complete")
	}
}

func TestNewHealthCheck(t *testing.T) {
	t.Parallel()

	called := false
	hc := NewHealthCheck("test-check", func(ctx context.Context) error {
		called = true
		return nil
	})

	if hc.Name() != "test-check" {
		t.Errorf("Name() = %q, want %q", hc.Name(), "test-check")
	}

	err := hc.Check(context.Background())
	if err != nil {
		t.Errorf("Check() returned error: %v", err)
	}
	if !called {
		t.Error("Check() did not call function")
	}
}

func TestNewInitializer(t *testing.T) {
	t.Parallel()

	called := false
	init := NewInitializer("test-init", func(ctx context.Context) error {
		called = true
		return nil
	})

	if init.Name() != "test-init" {
		t.Errorf("Name() = %q, want %q", init.Name(), "test-init")
	}

	err := init.Init(context.Background())
	if err != nil {
		t.Errorf("Init() returned error: %v", err)
	}
	if !called {
		t.Error("Init() did not call function")
	}
}

func TestNewCloser(t *testing.T) {
	t.Parallel()

	called := false
	closer := NewCloser("test-close", func(ctx context.Context) error {
		called = true
		return nil
	})

	if closer.Name() != "test-close" {
		t.Errorf("Name() = %q, want %q", closer.Name(), "test-close")
	}

	err := closer.Close(context.Background())
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
	if !called {
		t.Error("Close() did not call function")
	}
}

func TestApp_CloserError(t *testing.T) {
	t.Parallel()

	app := New(Config{
		Name:            "test",
		Version:         "1.0.0",
		ShutdownTimeout: 1 * time.Second,
		StartupTimeout:  1 * time.Second,
	})
	app.signalNotify = func(c chan<- os.Signal, sig ...os.Signal) {}

	app.RegisterCloser(NewCloser("failing", func(ctx context.Context) error {
		return errors.New("close error")
	}))

	done := make(chan error, 1)
	go func() {
		done <- app.Run()
	}()

	// Wait for running state.
	for i := 0; i < 100; i++ {
		if app.State() == StateRunning {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	app.Shutdown()

	select {
	case err := <-done:
		if err == nil {
			t.Error("Run() should return error when closer fails")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not complete")
	}
}
