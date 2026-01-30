package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	txcontext "github.com/Dorico-Dynamics/txova-go-core/context"
	"github.com/Dorico-Dynamics/txova-go-core/errors"
	"github.com/Dorico-Dynamics/txova-go-core/logging"
)

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	if cfg.Host != "0.0.0.0" {
		t.Errorf("Host = %v, want 0.0.0.0", cfg.Host)
	}
	if cfg.Port != 8080 {
		t.Errorf("Port = %v, want 8080", cfg.Port)
	}
	if cfg.ReadTimeout != 30*time.Second {
		t.Errorf("ReadTimeout = %v, want 30s", cfg.ReadTimeout)
	}
	if cfg.CORSConfig == nil {
		t.Error("CORSConfig should not be nil")
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("with logger", func(t *testing.T) {
		t.Parallel()
		logger := logging.New(logging.DefaultConfig())
		srv := New(DefaultConfig(), logger)
		if srv == nil {
			t.Fatal("New() returned nil")
		}
		if srv.Router() == nil {
			t.Error("Router() should not be nil")
		}
	})

	t.Run("without logger", func(t *testing.T) {
		t.Parallel()
		srv := New(DefaultConfig(), nil)
		if srv == nil {
			t.Fatal("New() returned nil")
		}
	})
}

func TestServer_Address(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	cfg.Host = "127.0.0.1"
	cfg.Port = 9000
	srv := New(cfg, nil)

	if got := srv.Address(); got != "127.0.0.1:9000" {
		t.Errorf("Address() = %v, want 127.0.0.1:9000", got)
	}
}

func TestRequestIDMiddleware(t *testing.T) {
	t.Parallel()

	srv := New(DefaultConfig(), nil)
	srv.Router().Get("/test", func(w http.ResponseWriter, r *http.Request) {
		requestID := txcontext.RequestID(r.Context())
		_, _ = w.Write([]byte(requestID))
	})

	t.Run("generates request ID", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		srv.Router().ServeHTTP(rec, req)

		// Should have request ID in response header.
		respID := rec.Header().Get("X-Request-ID")
		if respID == "" {
			t.Error("response should have X-Request-ID header")
		}
		if !strings.HasPrefix(respID, "req-") {
			t.Errorf("request ID should start with 'req-', got %v", respID)
		}

		// Body should contain the request ID.
		if rec.Body.String() != respID {
			t.Errorf("body = %v, want %v", rec.Body.String(), respID)
		}
	})

	t.Run("uses provided request ID", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Request-ID", "custom-id-123")
		rec := httptest.NewRecorder()
		srv.Router().ServeHTTP(rec, req)

		if rec.Header().Get("X-Request-ID") != "custom-id-123" {
			t.Error("should use provided request ID")
		}
	})

	t.Run("propagates correlation ID", func(t *testing.T) {
		t.Parallel()
		srv2 := New(DefaultConfig(), nil)
		srv2.Router().Get("/corr", func(w http.ResponseWriter, r *http.Request) {
			corrID := txcontext.CorrelationID(r.Context())
			_, _ = w.Write([]byte(corrID))
		})

		req := httptest.NewRequest(http.MethodGet, "/corr", nil)
		req.Header.Set("X-Correlation-ID", "corr-456")
		rec := httptest.NewRecorder()
		srv2.Router().ServeHTTP(rec, req)

		if rec.Body.String() != "corr-456" {
			t.Errorf("correlation ID = %v, want corr-456", rec.Body.String())
		}
	})
}

func TestRecoveryMiddleware(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := logging.New(logging.Config{
		Format: logging.FormatJSON,
		Output: &buf,
	})
	srv := New(DefaultConfig(), logger)
	srv.Router().Get("/panic", func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %v, want %v", rec.Code, http.StatusInternalServerError)
	}

	var resp Response
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("response should have error")
	}
	if resp.Error.Code != "INTERNAL_ERROR" {
		t.Errorf("error code = %v, want INTERNAL_ERROR", resp.Error.Code)
	}
	if resp.Error.Message != "an internal error occurred" {
		t.Errorf("error message should not expose panic details")
	}
}

func TestLoggingMiddleware(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := logging.New(logging.Config{
		Format: logging.FormatJSON,
		Output: &buf,
	})
	srv := New(DefaultConfig(), logger)
	srv.Router().Get("/logged", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	req := httptest.NewRequest(http.MethodGet, "/logged", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %v, want %v", rec.Code, http.StatusOK)
	}
}

func TestTimeoutMiddleware(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	cfg.RequestTimeout = 50 * time.Millisecond
	srv := New(cfg, nil)

	var contextCancelled bool
	srv.Router().Get("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(200 * time.Millisecond):
			_, _ = w.Write([]byte("completed"))
		case <-r.Context().Done():
			contextCancelled = true
			return
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/slow", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	// Context should be cancelled due to timeout.
	if !contextCancelled {
		t.Error("context should be cancelled on timeout")
	}
}

func TestCORSMiddleware(t *testing.T) {
	t.Parallel()

	t.Run("allows all origins with wildcard", func(t *testing.T) {
		t.Parallel()
		srv := New(DefaultConfig(), nil)
		srv.Router().Get("/cors", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("ok"))
		})

		req := httptest.NewRequest(http.MethodGet, "/cors", nil)
		req.Header.Set("Origin", "https://example.com")
		rec := httptest.NewRecorder()
		srv.Router().ServeHTTP(rec, req)

		if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Error("should allow all origins with wildcard")
		}
	})

	t.Run("handles preflight", func(t *testing.T) {
		t.Parallel()
		srv := New(DefaultConfig(), nil)
		srv.Router().Get("/cors", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("ok"))
		})

		req := httptest.NewRequest(http.MethodOptions, "/cors", nil)
		req.Header.Set("Origin", "https://example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		rec := httptest.NewRecorder()
		srv.Router().ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Errorf("preflight status = %v, want %v", rec.Code, http.StatusNoContent)
		}
		if rec.Header().Get("Access-Control-Allow-Methods") == "" {
			t.Error("should have Access-Control-Allow-Methods header")
		}
	})

	t.Run("specific origin", func(t *testing.T) {
		t.Parallel()
		cfg := DefaultConfig()
		cfg.CORSConfig.AllowedOrigins = []string{"https://allowed.com"}
		srv := New(cfg, nil)
		srv.Router().Get("/cors", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("ok"))
		})

		// Allowed origin.
		req := httptest.NewRequest(http.MethodGet, "/cors", nil)
		req.Header.Set("Origin", "https://allowed.com")
		rec := httptest.NewRecorder()
		srv.Router().ServeHTTP(rec, req)

		if rec.Header().Get("Access-Control-Allow-Origin") != "https://allowed.com" {
			t.Error("should allow specific origin")
		}

		// Disallowed origin.
		req2 := httptest.NewRequest(http.MethodGet, "/cors", nil)
		req2.Header.Set("Origin", "https://notallowed.com")
		rec2 := httptest.NewRecorder()
		srv.Router().ServeHTTP(rec2, req2)

		if rec2.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Error("should not allow disallowed origin")
		}
	})
}

func TestWriteJSON(t *testing.T) {
	t.Parallel()

	data := map[string]string{"message": "hello"}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(txcontext.WithRequestID(req.Context(), "test-req-id"))
	rec := httptest.NewRecorder()

	WriteJSON(rec, req, http.StatusOK, data)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %v, want %v", rec.Code, http.StatusOK)
	}
	if rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %v", rec.Header().Get("Content-Type"))
	}

	var resp Response
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Data == nil {
		t.Fatal("data should not be nil")
	}
	if resp.Meta == nil {
		t.Fatal("meta should not be nil")
	}
	if resp.Meta.RequestID != "test-req-id" {
		t.Errorf("request_id = %v, want test-req-id", resp.Meta.RequestID)
	}
	if resp.Meta.Timestamp == "" {
		t.Error("timestamp should not be empty")
	}
}

func TestWriteJSONWithPagination(t *testing.T) {
	t.Parallel()

	data := []string{"item1", "item2"}
	pagination := PaginationMeta{Page: 1, PerPage: 10, Total: 100, TotalPages: 10}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	WriteJSONWithPagination(rec, req, http.StatusOK, data, pagination)

	var resp Response
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Meta.Page != 1 {
		t.Errorf("page = %v, want 1", resp.Meta.Page)
	}
	if resp.Meta.Total != 100 {
		t.Errorf("total = %v, want 100", resp.Meta.Total)
	}
}

func TestWriteError(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	WriteError(rec, http.StatusBadRequest, "VALIDATION_ERROR", "invalid input")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %v, want %v", rec.Code, http.StatusBadRequest)
	}

	var resp Response
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("error should not be nil")
	}
	if resp.Error.Code != "VALIDATION_ERROR" {
		t.Errorf("code = %v, want VALIDATION_ERROR", resp.Error.Code)
	}
	if resp.Error.Message != "invalid input" {
		t.Errorf("message = %v, want 'invalid input'", resp.Error.Message)
	}
}

func TestWriteAppError(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(txcontext.WithRequestID(req.Context(), "req-123"))
	rec := httptest.NewRecorder()

	err := errors.NotFound("user not found")
	WriteAppError(rec, req, err)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %v, want %v", rec.Code, http.StatusNotFound)
	}

	var resp Response
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error.Code != "NOT_FOUND" {
		t.Errorf("code = %v, want NOT_FOUND", resp.Error.Code)
	}
	if resp.Meta.RequestID != "req-123" {
		t.Errorf("request_id = %v, want req-123", resp.Meta.RequestID)
	}
}

func TestWriteAppError_SanitizesInternalError(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	err := errors.InternalError("database connection failed: password=secret123")
	WriteAppError(rec, req, err)

	var resp Response
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error.Message != "an internal error occurred" {
		t.Errorf("internal error details should be sanitized, got: %v", resp.Error.Message)
	}
}

func TestHandleError(t *testing.T) {
	t.Parallel()

	t.Run("handles AppError", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		HandleError(rec, req, errors.Forbidden("access denied"))

		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %v, want %v", rec.Code, http.StatusForbidden)
		}
	})

	t.Run("handles generic error", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		HandleError(rec, req, context.DeadlineExceeded)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status = %v, want %v", rec.Code, http.StatusInternalServerError)
		}
	})
}

func TestResponseHelpers(t *testing.T) {
	t.Parallel()

	t.Run("OK", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		OK(rec, req, "success")
		if rec.Code != http.StatusOK {
			t.Errorf("status = %v, want %v", rec.Code, http.StatusOK)
		}
	})

	t.Run("Created", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		rec := httptest.NewRecorder()
		Created(rec, req, map[string]string{"id": "123"})
		if rec.Code != http.StatusCreated {
			t.Errorf("status = %v, want %v", rec.Code, http.StatusCreated)
		}
	})

	t.Run("NoContent", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		NoContent(rec)
		if rec.Code != http.StatusNoContent {
			t.Errorf("status = %v, want %v", rec.Code, http.StatusNoContent)
		}
	})

	t.Run("BadRequest", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		rec := httptest.NewRecorder()
		BadRequest(rec, req, "invalid input")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %v, want %v", rec.Code, http.StatusBadRequest)
		}
	})

	t.Run("Unauthorized", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		Unauthorized(rec, req, "invalid token")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %v, want %v", rec.Code, http.StatusUnauthorized)
		}
	})

	t.Run("Forbidden", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		Forbidden(rec, req, "access denied")
		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %v, want %v", rec.Code, http.StatusForbidden)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		NotFound(rec, req, "resource not found")
		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %v, want %v", rec.Code, http.StatusNotFound)
		}
	})

	t.Run("Conflict", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		rec := httptest.NewRecorder()
		Conflict(rec, req, "already exists")
		if rec.Code != http.StatusConflict {
			t.Errorf("status = %v, want %v", rec.Code, http.StatusConflict)
		}
	})

	t.Run("InternalError", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		InternalError(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status = %v, want %v", rec.Code, http.StatusInternalServerError)
		}
	})
}

func TestDecodeJSON(t *testing.T) {
	t.Parallel()

	t.Run("valid JSON", func(t *testing.T) {
		t.Parallel()
		body := strings.NewReader(`{"name":"test","value":123}`)
		req := httptest.NewRequest(http.MethodPost, "/", body)

		var data struct {
			Name  string `json:"name"`
			Value int    `json:"value"`
		}

		err := DecodeJSON(req, &data)
		if err != nil {
			t.Fatalf("DecodeJSON() error = %v", err)
		}

		if data.Name != "test" {
			t.Errorf("Name = %v, want test", data.Name)
		}
		if data.Value != 123 {
			t.Errorf("Value = %v, want 123", data.Value)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		t.Parallel()
		body := strings.NewReader(`{invalid}`)
		req := httptest.NewRequest(http.MethodPost, "/", body)

		var data struct{}
		err := DecodeJSON(req, &data)
		if err == nil {
			t.Fatal("DecodeJSON() should fail with invalid JSON")
		}
		if !errors.IsValidationError(err) {
			t.Errorf("error should be validation error, got: %v", err)
		}
	})

	t.Run("nil body", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Body = nil

		var data struct{}
		err := DecodeJSON(req, &data)
		if err == nil {
			t.Fatal("DecodeJSON() should fail with nil body")
		}
	})

	t.Run("unknown fields", func(t *testing.T) {
		t.Parallel()
		body := strings.NewReader(`{"name":"test","unknown":"field"}`)
		req := httptest.NewRequest(http.MethodPost, "/", body)

		var data struct {
			Name string `json:"name"`
		}

		err := DecodeJSON(req, &data)
		if err == nil {
			t.Fatal("DecodeJSON() should fail with unknown fields")
		}
	})
}

func TestResponseWriter(t *testing.T) {
	t.Parallel()

	t.Run("captures status code", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		rw := &responseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

		rw.WriteHeader(http.StatusCreated)
		if rw.statusCode != http.StatusCreated {
			t.Errorf("statusCode = %v, want %v", rw.statusCode, http.StatusCreated)
		}
	})

	t.Run("only captures first status", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		rw := &responseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

		rw.WriteHeader(http.StatusCreated)
		rw.WriteHeader(http.StatusNotFound) // Should be ignored.
		if rw.statusCode != http.StatusCreated {
			t.Errorf("statusCode = %v, want %v", rw.statusCode, http.StatusCreated)
		}
	})
}

func TestGetRemoteAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		xff        string
		xri        string
		remoteAddr string
		expected   string
	}{
		{"X-Forwarded-For single", "192.168.1.1", "", "", "192.168.1.1"},
		{"X-Forwarded-For multiple", "192.168.1.1, 10.0.0.1", "", "", "192.168.1.1"},
		{"X-Real-IP", "", "192.168.1.2", "", "192.168.1.2"},
		{"RemoteAddr with port", "", "", "192.168.1.3:12345", "192.168.1.3"},
		{"RemoteAddr without port", "", "", "192.168.1.4", "192.168.1.4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				req.Header.Set("X-Real-IP", tt.xri)
			}
			if tt.remoteAddr != "" {
				req.RemoteAddr = tt.remoteAddr
			}

			got := getRemoteAddr(req)
			if got != tt.expected {
				t.Errorf("getRemoteAddr() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestItoa(t *testing.T) {
	t.Parallel()

	tests := []struct {
		n        int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{123, "123"},
		{-1, "-1"},
		{-123, "-123"},
		{8080, "8080"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			t.Parallel()
			if got := itoa(tt.n); got != tt.expected {
				t.Errorf("itoa(%d) = %v, want %v", tt.n, got, tt.expected)
			}
		})
	}
}
