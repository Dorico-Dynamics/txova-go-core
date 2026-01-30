package errors

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCode_HTTPStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		code     Code
		expected int
	}{
		{"validation error", CodeValidationError, http.StatusBadRequest},
		{"invalid credentials", CodeInvalidCredentials, http.StatusUnauthorized},
		{"token expired", CodeTokenExpired, http.StatusUnauthorized},
		{"token invalid", CodeTokenInvalid, http.StatusUnauthorized},
		{"forbidden", CodeForbidden, http.StatusForbidden},
		{"not found", CodeNotFound, http.StatusNotFound},
		{"conflict", CodeConflict, http.StatusConflict},
		{"rate limited", CodeRateLimited, http.StatusTooManyRequests},
		{"internal error", CodeInternalError, http.StatusInternalServerError},
		{"service unavailable", CodeServiceUnavailable, http.StatusServiceUnavailable},
		{"unknown code", Code("UNKNOWN"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.code.HTTPStatus(); got != tt.expected {
				t.Errorf("Code.HTTPStatus() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCode_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		code     Code
		expected string
	}{
		{CodeValidationError, "VALIDATION_ERROR"},
		{CodeNotFound, "NOT_FOUND"},
		{CodeInternalError, "INTERNAL_ERROR"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			t.Parallel()
			if got := tt.code.String(); got != tt.expected {
				t.Errorf("Code.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	err := New(CodeNotFound, "user not found")

	if err.Code() != CodeNotFound {
		t.Errorf("Code() = %v, want %v", err.Code(), CodeNotFound)
	}
	if err.Message() != "user not found" {
		t.Errorf("Message() = %v, want %v", err.Message(), "user not found")
	}
	if err.Unwrap() != nil {
		t.Errorf("Unwrap() = %v, want nil", err.Unwrap())
	}
}

func TestWrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("database connection failed")
	err := Wrap(CodeServiceUnavailable, "unable to fetch user", cause)

	if err.Code() != CodeServiceUnavailable {
		t.Errorf("Code() = %v, want %v", err.Code(), CodeServiceUnavailable)
	}
	if err.Message() != "unable to fetch user" {
		t.Errorf("Message() = %v, want %v", err.Message(), "unable to fetch user")
	}
	if err.Unwrap() != cause {
		t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
	}
}

func TestAppError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *AppError
		expected string
	}{
		{
			name:     "without cause",
			err:      New(CodeNotFound, "resource not found"),
			expected: "NOT_FOUND: resource not found",
		},
		{
			name:     "with cause",
			err:      Wrap(CodeInternalError, "failed to process", errors.New("timeout")),
			expected: "INTERNAL_ERROR: failed to process: timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAppError_HTTPStatus(t *testing.T) {
	t.Parallel()

	err := NotFound("user not found")
	if got := err.HTTPStatus(); got != http.StatusNotFound {
		t.Errorf("HTTPStatus() = %v, want %v", got, http.StatusNotFound)
	}
}

func TestAppError_Is(t *testing.T) {
	t.Parallel()

	err1 := NotFound("resource A not found")
	err2 := NotFound("resource B not found")
	err3 := Forbidden("access denied")

	if !err1.Is(err2) {
		t.Error("Is() should return true for errors with same code")
	}
	if err1.Is(err3) {
		t.Error("Is() should return false for errors with different code")
	}
	if err1.Is(errors.New("plain error")) {
		t.Error("Is() should return false for non-AppError")
	}
}

func TestAppError_WithMessage(t *testing.T) {
	t.Parallel()

	original := NotFound("original message")
	modified := original.WithMessage("new message")

	if modified.Code() != original.Code() {
		t.Errorf("WithMessage() changed code: got %v, want %v", modified.Code(), original.Code())
	}
	if modified.Message() != "new message" {
		t.Errorf("WithMessage() message = %v, want %v", modified.Message(), "new message")
	}
	if original.Message() != "original message" {
		t.Error("WithMessage() should not modify original")
	}
}

func TestAppError_WithCause(t *testing.T) {
	t.Parallel()

	original := InternalError("processing failed")
	cause := errors.New("timeout")
	modified := original.WithCause(cause)

	if modified.Code() != original.Code() {
		t.Errorf("WithCause() changed code: got %v, want %v", modified.Code(), original.Code())
	}
	if modified.Message() != original.Message() {
		t.Errorf("WithCause() changed message: got %v, want %v", modified.Message(), original.Message())
	}
	if modified.Unwrap() != cause {
		t.Errorf("WithCause() cause = %v, want %v", modified.Unwrap(), cause)
	}
	if original.Unwrap() != nil {
		t.Error("WithCause() should not modify original")
	}
}

func TestAppError_ToResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		err             *AppError
		expectedCode    string
		expectedMessage string
	}{
		{
			name:            "validation error preserves message",
			err:             ValidationError("field 'email' is required"),
			expectedCode:    "VALIDATION_ERROR",
			expectedMessage: "field 'email' is required",
		},
		{
			name:            "not found error preserves message",
			err:             NotFound("user with ID 123 not found"),
			expectedCode:    "NOT_FOUND",
			expectedMessage: "user with ID 123 not found",
		},
		{
			name:            "internal error hides message",
			err:             InternalError("database query failed: SELECT * FROM users"),
			expectedCode:    "INTERNAL_ERROR",
			expectedMessage: "an internal error occurred",
		},
		{
			name:            "internal error with cause hides details",
			err:             InternalErrorWrap("failed to connect", errors.New("password authentication failed")),
			expectedCode:    "INTERNAL_ERROR",
			expectedMessage: "an internal error occurred",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp := tt.err.ToResponse()
			if resp.Error.Code != tt.expectedCode {
				t.Errorf("ToResponse().Error.Code = %v, want %v", resp.Error.Code, tt.expectedCode)
			}
			if resp.Error.Message != tt.expectedMessage {
				t.Errorf("ToResponse().Error.Message = %v, want %v", resp.Error.Message, tt.expectedMessage)
			}
		})
	}
}

func TestAppError_WriteJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		err                 *AppError
		expectedStatus      int
		expectedCode        string
		expectedMessage     string
		checkContentType    bool
		expectedContentType string
	}{
		{
			name:                "not found error",
			err:                 NotFound("user not found"),
			expectedStatus:      http.StatusNotFound,
			expectedCode:        "NOT_FOUND",
			expectedMessage:     "user not found",
			checkContentType:    true,
			expectedContentType: "application/json; charset=utf-8",
		},
		{
			name:            "internal error sanitizes message",
			err:             InternalError("secret database info"),
			expectedStatus:  http.StatusInternalServerError,
			expectedCode:    "INTERNAL_ERROR",
			expectedMessage: "an internal error occurred",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			err := tt.err.WriteJSON(w)
			if err != nil {
				t.Fatalf("WriteJSON() error = %v", err)
			}

			if w.Code != tt.expectedStatus {
				t.Errorf("WriteJSON() status = %v, want %v", w.Code, tt.expectedStatus)
			}

			if tt.checkContentType {
				ct := w.Header().Get("Content-Type")
				if ct != tt.expectedContentType {
					t.Errorf("WriteJSON() Content-Type = %v, want %v", ct, tt.expectedContentType)
				}
			}

			var resp ErrorResponse
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if resp.Error.Code != tt.expectedCode {
				t.Errorf("WriteJSON() code = %v, want %v", resp.Error.Code, tt.expectedCode)
			}
			if resp.Error.Message != tt.expectedMessage {
				t.Errorf("WriteJSON() message = %v, want %v", resp.Error.Message, tt.expectedMessage)
			}
		})
	}
}

func TestConstructors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		constructor  func() *AppError
		expectedCode Code
		expectedHTTP int
	}{
		{"ValidationError", func() *AppError { return ValidationError("invalid") }, CodeValidationError, http.StatusBadRequest},
		{"ValidationErrorf", func() *AppError { return ValidationErrorf("field %s invalid", "email") }, CodeValidationError, http.StatusBadRequest},
		{"InvalidCredentials", func() *AppError { return InvalidCredentials("wrong password") }, CodeInvalidCredentials, http.StatusUnauthorized},
		{"TokenExpired", func() *AppError { return TokenExpired("token has expired") }, CodeTokenExpired, http.StatusUnauthorized},
		{"TokenInvalid", func() *AppError { return TokenInvalid("invalid signature") }, CodeTokenInvalid, http.StatusUnauthorized},
		{"Forbidden", func() *AppError { return Forbidden("access denied") }, CodeForbidden, http.StatusForbidden},
		{"NotFound", func() *AppError { return NotFound("not found") }, CodeNotFound, http.StatusNotFound},
		{"NotFoundf", func() *AppError { return NotFoundf("user %s not found", "123") }, CodeNotFound, http.StatusNotFound},
		{"Conflict", func() *AppError { return Conflict("already exists") }, CodeConflict, http.StatusConflict},
		{"Conflictf", func() *AppError { return Conflictf("user %s exists", "test@example.com") }, CodeConflict, http.StatusConflict},
		{"RateLimited", func() *AppError { return RateLimited("too many requests") }, CodeRateLimited, http.StatusTooManyRequests},
		{"InternalError", func() *AppError { return InternalError("internal") }, CodeInternalError, http.StatusInternalServerError},
		{"InternalErrorf", func() *AppError { return InternalErrorf("error: %v", "details") }, CodeInternalError, http.StatusInternalServerError},
		{"ServiceUnavailable", func() *AppError { return ServiceUnavailable("service down") }, CodeServiceUnavailable, http.StatusServiceUnavailable},
		{"ServiceUnavailablef", func() *AppError { return ServiceUnavailablef("service %s down", "db") }, CodeServiceUnavailable, http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.constructor()
			if err.Code() != tt.expectedCode {
				t.Errorf("Code() = %v, want %v", err.Code(), tt.expectedCode)
			}
			if err.HTTPStatus() != tt.expectedHTTP {
				t.Errorf("HTTPStatus() = %v, want %v", err.HTTPStatus(), tt.expectedHTTP)
			}
		})
	}
}

func TestInternalErrorWrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("underlying error")
	err := InternalErrorWrap("operation failed", cause)

	if err.Code() != CodeInternalError {
		t.Errorf("Code() = %v, want %v", err.Code(), CodeInternalError)
	}
	if err.Unwrap() != cause {
		t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
	}
}

func TestIsAppError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"AppError", NotFound("not found"), true},
		{"wrapped AppError", Wrap(CodeNotFound, "msg", errors.New("cause")), true},
		{"plain error", errors.New("plain error"), false},
		{"nil error", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsAppError(tt.err); got != tt.expected {
				t.Errorf("IsAppError() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAsAppError(t *testing.T) {
	t.Parallel()

	appErr := NotFound("not found")
	plainErr := errors.New("plain error")

	if got := AsAppError(appErr); got != appErr {
		t.Errorf("AsAppError(AppError) = %v, want %v", got, appErr)
	}
	if got := AsAppError(plainErr); got != nil {
		t.Errorf("AsAppError(plain error) = %v, want nil", got)
	}
	if got := AsAppError(nil); got != nil {
		t.Errorf("AsAppError(nil) = %v, want nil", got)
	}
}

func TestGetCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected Code
	}{
		{"AppError", NotFound("not found"), CodeNotFound},
		{"plain error", errors.New("plain"), CodeInternalError},
		{"nil error", nil, CodeInternalError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := GetCode(tt.err); got != tt.expected {
				t.Errorf("GetCode() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGetHTTPStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected int
	}{
		{"AppError", NotFound("not found"), http.StatusNotFound},
		{"plain error", errors.New("plain"), http.StatusInternalServerError},
		{"nil error", nil, http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := GetHTTPStatus(tt.err); got != tt.expected {
				t.Errorf("GetHTTPStatus() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestFromError(t *testing.T) {
	t.Parallel()

	appErr := NotFound("not found")
	plainErr := errors.New("plain error")

	t.Run("returns AppError as-is", func(t *testing.T) {
		t.Parallel()
		if got := FromError(appErr); got != appErr {
			t.Errorf("FromError(AppError) = %v, want %v", got, appErr)
		}
	})

	t.Run("wraps plain error as InternalError", func(t *testing.T) {
		t.Parallel()
		got := FromError(plainErr)
		if got.Code() != CodeInternalError {
			t.Errorf("FromError(plain).Code() = %v, want %v", got.Code(), CodeInternalError)
		}
		if got.Unwrap() != plainErr {
			t.Errorf("FromError(plain).Unwrap() = %v, want %v", got.Unwrap(), plainErr)
		}
	})
}

func TestIsCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		code     Code
		expected bool
	}{
		{"matching code", NotFound("not found"), CodeNotFound, true},
		{"different code", NotFound("not found"), CodeForbidden, false},
		{"plain error", errors.New("plain"), CodeNotFound, false},
		{"nil error", nil, CodeNotFound, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsCode(tt.err, tt.code); got != tt.expected {
				t.Errorf("IsCode() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsCheckers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		checker  func(error) bool
		err      error
		expected bool
	}{
		{"IsValidationError true", IsValidationError, ValidationError("invalid"), true},
		{"IsValidationError false", IsValidationError, NotFound("not found"), false},
		{"IsNotFound true", IsNotFound, NotFound("not found"), true},
		{"IsNotFound false", IsNotFound, Forbidden("denied"), false},
		{"IsForbidden true", IsForbidden, Forbidden("denied"), true},
		{"IsForbidden false", IsForbidden, NotFound("not found"), false},
		{"IsUnauthorized with InvalidCredentials", IsUnauthorized, InvalidCredentials("wrong"), true},
		{"IsUnauthorized with TokenExpired", IsUnauthorized, TokenExpired("expired"), true},
		{"IsUnauthorized with TokenInvalid", IsUnauthorized, TokenInvalid("invalid"), true},
		{"IsUnauthorized false", IsUnauthorized, NotFound("not found"), false},
		{"IsConflict true", IsConflict, Conflict("exists"), true},
		{"IsConflict false", IsConflict, NotFound("not found"), false},
		{"IsInternalError true", IsInternalError, InternalError("error"), true},
		{"IsInternalError false", IsInternalError, NotFound("not found"), false},
		{"IsServiceUnavailable true", IsServiceUnavailable, ServiceUnavailable("down"), true},
		{"IsServiceUnavailable false", IsServiceUnavailable, NotFound("not found"), false},
		{"IsRateLimited true", IsRateLimited, RateLimited("too many"), true},
		{"IsRateLimited false", IsRateLimited, NotFound("not found"), false},
		{"plain error returns false", IsNotFound, errors.New("plain"), false},
		{"nil error returns false", IsNotFound, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.checker(tt.err); got != tt.expected {
				t.Errorf("checker() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestErrorsAs(t *testing.T) {
	t.Parallel()

	appErr := NotFound("not found")
	wrappedErr := Wrap(CodeInternalError, "wrapped", appErr)

	var target *AppError
	if !errors.As(wrappedErr, &target) {
		t.Error("errors.As should find AppError in wrapped error")
	}

	// Verify the wrapped cause can be extracted.
	if target.Unwrap() != appErr {
		t.Errorf("Unwrap() = %v, want %v", target.Unwrap(), appErr)
	}
}

func TestErrorsIs(t *testing.T) {
	t.Parallel()

	err1 := NotFound("resource A")
	err2 := NotFound("resource B")

	// Custom Is implementation allows same-code matching.
	if !errors.Is(err1, err2) {
		t.Error("errors.Is should return true for AppErrors with same code")
	}
}

func TestFormattedConstructors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		err         *AppError
		expectedMsg string
	}{
		{
			name:        "ValidationErrorf",
			err:         ValidationErrorf("field '%s' must be %d characters", "username", 5),
			expectedMsg: "field 'username' must be 5 characters",
		},
		{
			name:        "NotFoundf",
			err:         NotFoundf("user with ID %d not found", 12345),
			expectedMsg: "user with ID 12345 not found",
		},
		{
			name:        "Conflictf",
			err:         Conflictf("email %s already registered", "test@example.com"),
			expectedMsg: "email test@example.com already registered",
		},
		{
			name:        "InternalErrorf",
			err:         InternalErrorf("failed to connect to %s on port %d", "localhost", 5432),
			expectedMsg: "failed to connect to localhost on port 5432",
		},
		{
			name:        "ServiceUnavailablef",
			err:         ServiceUnavailablef("service %s is unavailable", "payment-gateway"),
			expectedMsg: "service payment-gateway is unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.err.Message() != tt.expectedMsg {
				t.Errorf("Message() = %v, want %v", tt.err.Message(), tt.expectedMsg)
			}
		})
	}
}
