package app

import (
	"context"
	"net/http"
	"time"

	"github.com/Dorico-Dynamics/txova-go-core/server"
)

// HealthHandler provides HTTP handlers for health check endpoints.
type HealthHandler struct {
	app *App
}

// NewHealthHandler creates a new HealthHandler for the given app.
func NewHealthHandler(app *App) *HealthHandler {
	return &HealthHandler{app: app}
}

// LivenessHandler returns an HTTP handler for the liveness probe.
// Returns 200 OK if the application is live (not stopped).
// This endpoint should be used by Kubernetes liveness probes.
func (h *HealthHandler) LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.app.IsLive() {
			server.WriteJSON(w, r, http.StatusOK, map[string]string{
				"status": "live",
			})
			return
		}

		server.WriteJSON(w, r, http.StatusServiceUnavailable, map[string]string{
			"status": "dead",
		})
	}
}

// ReadinessHandler returns an HTTP handler for the readiness probe.
// Returns 200 OK if the application is ready to serve requests.
// This endpoint should be used by Kubernetes readiness probes.
func (h *HealthHandler) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		report := h.app.CheckHealth(ctx)

		status := http.StatusOK
		if report.Status != StatusHealthy {
			status = http.StatusServiceUnavailable
		}

		// Also check if app is in running state.
		if h.app.State() != StateRunning {
			status = http.StatusServiceUnavailable
			report.Status = "not_ready"
		}

		server.WriteJSON(w, r, status, report)
	}
}

// HealthHandler returns an HTTP handler for the full health check.
// Returns detailed health information about all components.
func (h *HealthHandler) HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		report := h.app.CheckHealth(ctx)

		// Add application metadata.
		type healthResponse struct {
			HealthReport
			App struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				State   string `json:"state"`
			} `json:"app"`
		}

		resp := healthResponse{
			HealthReport: report,
		}
		resp.App.Name = h.app.config.Name
		resp.App.Version = h.app.config.Version
		resp.App.State = h.app.State().String()

		status := http.StatusOK
		if report.Status != StatusHealthy || h.app.State() != StateRunning {
			status = http.StatusServiceUnavailable
		}

		server.WriteJSON(w, r, status, resp)
	}
}

// RegisterHealthRoutes registers health endpoints on the given server.
// Routes:
//   - GET /health/live  - Liveness probe
//   - GET /health/ready - Readiness probe
//   - GET /health       - Full health check
func RegisterHealthRoutes(srv *server.Server, app *App) {
	h := NewHealthHandler(app)
	router := srv.Router()

	router.Get("/health", h.HealthHandler())
	router.Get("/health/live", h.LivenessHandler())
	router.Get("/health/ready", h.ReadinessHandler())
}
