package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Dorico-Dynamics/txova-go-core/server"
)

// responseEnvelope wraps the server response envelope for testing.
type responseEnvelope struct {
	Data json.RawMessage       `json:"data"`
	Meta *server.Meta          `json:"meta,omitempty"`
	Err  *server.ErrorResponse `json:"error,omitempty"`
}

func TestHealthHandler_LivenessHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		state      State
		wantStatus int
		wantBody   string
	}{
		{
			name:       "live when created",
			state:      StateCreated,
			wantStatus: http.StatusOK,
			wantBody:   "live",
		},
		{
			name:       "live when starting",
			state:      StateStarting,
			wantStatus: http.StatusOK,
			wantBody:   "live",
		},
		{
			name:       "live when running",
			state:      StateRunning,
			wantStatus: http.StatusOK,
			wantBody:   "live",
		},
		{
			name:       "live when shutting down",
			state:      StateShuttingDown,
			wantStatus: http.StatusOK,
			wantBody:   "live",
		},
		{
			name:       "dead when stopped",
			state:      StateStopped,
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   "dead",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			app := New(DefaultConfig())
			app.state.Store(int32(tt.state))

			handler := NewHealthHandler(app)
			req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
			rec := httptest.NewRecorder()

			handler.LivenessHandler()(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			var envelope responseEnvelope
			if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("failed to parse envelope: %v", err)
			}

			var resp map[string]string
			if err := json.Unmarshal(envelope.Data, &resp); err != nil {
				t.Fatalf("failed to parse data: %v", err)
			}

			if resp["status"] != tt.wantBody {
				t.Errorf("status = %q, want %q", resp["status"], tt.wantBody)
			}
		})
	}
}

func TestHealthHandler_ReadinessHandler(t *testing.T) {
	t.Parallel()

	t.Run("ready when running with healthy checks", func(t *testing.T) {
		t.Parallel()

		app := New(DefaultConfig())
		app.state.Store(int32(StateRunning))
		app.RegisterHealthCheck(NewHealthCheck("db", func(ctx context.Context) error {
			return nil
		}))

		handler := NewHealthHandler(app)
		req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
		rec := httptest.NewRecorder()

		handler.ReadinessHandler()(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
		}

		var envelope responseEnvelope
		if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("failed to parse envelope: %v", err)
		}

		var resp HealthReport
		if err := json.Unmarshal(envelope.Data, &resp); err != nil {
			t.Fatalf("failed to parse data: %v", err)
		}

		if resp.Status != "healthy" {
			t.Errorf("status = %q, want %q", resp.Status, "healthy")
		}
	})

	t.Run("not ready when health check fails", func(t *testing.T) {
		t.Parallel()

		app := New(DefaultConfig())
		app.state.Store(int32(StateRunning))
		app.RegisterHealthCheck(NewHealthCheck("db", func(ctx context.Context) error {
			return errors.New("connection failed")
		}))

		handler := NewHealthHandler(app)
		req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
		rec := httptest.NewRecorder()

		handler.ReadinessHandler()(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
		}

		var envelope responseEnvelope
		if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("failed to parse envelope: %v", err)
		}

		var resp HealthReport
		if err := json.Unmarshal(envelope.Data, &resp); err != nil {
			t.Fatalf("failed to parse data: %v", err)
		}

		if resp.Status != "unhealthy" {
			t.Errorf("status = %q, want %q", resp.Status, "unhealthy")
		}
	})

	t.Run("not ready when not running", func(t *testing.T) {
		t.Parallel()

		app := New(DefaultConfig())
		app.state.Store(int32(StateStarting))

		handler := NewHealthHandler(app)
		req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
		rec := httptest.NewRecorder()

		handler.ReadinessHandler()(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
		}

		var envelope responseEnvelope
		if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("failed to parse envelope: %v", err)
		}

		var resp HealthReport
		if err := json.Unmarshal(envelope.Data, &resp); err != nil {
			t.Fatalf("failed to parse data: %v", err)
		}

		if resp.Status != "not_ready" {
			t.Errorf("status = %q, want %q", resp.Status, "not_ready")
		}
	})
}

func TestHealthHandler_HealthHandler(t *testing.T) {
	t.Parallel()

	t.Run("healthy with app metadata", func(t *testing.T) {
		t.Parallel()

		cfg := Config{
			Name:    "test-app",
			Version: "2.0.0",
		}
		app := New(cfg)
		app.state.Store(int32(StateRunning))

		handler := NewHealthHandler(app)
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()

		handler.HealthHandler()(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
		}

		var envelope responseEnvelope
		if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("failed to parse envelope: %v", err)
		}

		var resp struct {
			HealthReport
			App struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				State   string `json:"state"`
			} `json:"app"`
		}
		if err := json.Unmarshal(envelope.Data, &resp); err != nil {
			t.Fatalf("failed to parse data: %v", err)
		}

		if resp.App.Name != "test-app" {
			t.Errorf("app.name = %q, want %q", resp.App.Name, "test-app")
		}
		if resp.App.Version != "2.0.0" {
			t.Errorf("app.version = %q, want %q", resp.App.Version, "2.0.0")
		}
		if resp.App.State != "running" {
			t.Errorf("app.state = %q, want %q", resp.App.State, "running")
		}
	})

	t.Run("unhealthy when component fails", func(t *testing.T) {
		t.Parallel()

		app := New(DefaultConfig())
		app.state.Store(int32(StateRunning))
		app.RegisterHealthCheck(NewHealthCheck("redis", func(ctx context.Context) error {
			return errors.New("timeout")
		}))

		handler := NewHealthHandler(app)
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()

		handler.HealthHandler()(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
		}
	})

	t.Run("unhealthy when not running", func(t *testing.T) {
		t.Parallel()

		app := New(DefaultConfig())
		app.state.Store(int32(StateShuttingDown))

		handler := NewHealthHandler(app)
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()

		handler.HealthHandler()(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
		}
	})
}

func TestNewHealthHandler(t *testing.T) {
	t.Parallel()

	app := New(DefaultConfig())
	handler := NewHealthHandler(app)

	if handler.app != app {
		t.Error("handler.app should reference the provided app")
	}
}
