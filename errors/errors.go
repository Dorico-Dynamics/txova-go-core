// Package errors provides standardized error handling for the Txova platform.
// It defines application-level errors with machine-readable codes, HTTP status
// mappings, and support for error wrapping and unwrapping.
package errors

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Code represents a machine-readable error code.
type Code string

// Standard error codes for the Txova platform.
const (
	CodeValidationError    Code = "VALIDATION_ERROR"
	CodeInvalidCredentials Code = "INVALID_CREDENTIALS" // #nosec G101 -- this is an error code, not credentials
	CodeTokenExpired       Code = "TOKEN_EXPIRED"
	CodeTokenInvalid       Code = "TOKEN_INVALID"
	CodeForbidden          Code = "FORBIDDEN"
	CodeNotFound           Code = "NOT_FOUND"
	CodeConflict           Code = "CONFLICT"
	CodeRateLimited        Code = "RATE_LIMITED"
	CodeInternalError      Code = "INTERNAL_ERROR"
	CodeServiceUnavailable Code = "SERVICE_UNAVAILABLE"
)

// codeHTTPStatus maps error codes to their corresponding HTTP status codes.
var codeHTTPStatus = map[Code]int{
	CodeValidationError:    http.StatusBadRequest,
	CodeInvalidCredentials: http.StatusUnauthorized,
	CodeTokenExpired:       http.StatusUnauthorized,
	CodeTokenInvalid:       http.StatusUnauthorized,
	CodeForbidden:          http.StatusForbidden,
	CodeNotFound:           http.StatusNotFound,
	CodeConflict:           http.StatusConflict,
	CodeRateLimited:        http.StatusTooManyRequests,
	CodeInternalError:      http.StatusInternalServerError,
	CodeServiceUnavailable: http.StatusServiceUnavailable,
}

// RegisterHTTPStatus registers a mapping from an error code to an HTTP status
// code. This allows external packages to extend the error code system with
// their own domain-specific codes. Existing mappings are overwritten.
func RegisterHTTPStatus(code Code, status int) {
	codeHTTPStatus[code] = status
}

// HTTPStatus returns the HTTP status code for the given error code.
// Returns 500 Internal Server Error if the code is unknown.
func (c Code) HTTPStatus() int {
	if status, ok := codeHTTPStatus[c]; ok {
		return status
	}
	return http.StatusInternalServerError
}

// String returns the string representation of the error code.
func (c Code) String() string {
	return string(c)
}

// AppError represents an application-level error with a machine-readable code,
// human-readable message, HTTP status, and optional wrapped error.
type AppError struct {
	code    Code
	message string
	cause   error
}

// New creates a new AppError with the given code and message.
func New(code Code, message string) *AppError {
	return &AppError{
		code:    code,
		message: message,
	}
}

// Wrap creates a new AppError that wraps an existing error.
func Wrap(code Code, message string, cause error) *AppError {
	return &AppError{
		code:    code,
		message: message,
		cause:   cause,
	}
}

// Error implements the error interface.
func (e *AppError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.code, e.message, e.cause)
	}
	return fmt.Sprintf("%s: %s", e.code, e.message)
}

// Code returns the error code.
func (e *AppError) Code() Code {
	return e.code
}

// Message returns the human-readable error message.
func (e *AppError) Message() string {
	return e.message
}

// HTTPStatus returns the HTTP status code for this error.
func (e *AppError) HTTPStatus() int {
	return e.code.HTTPStatus()
}

// Unwrap returns the wrapped error, if any.
func (e *AppError) Unwrap() error {
	return e.cause
}

// Is reports whether the target error is an AppError with the same code.
func (e *AppError) Is(target error) bool {
	var appErr *AppError
	if errors.As(target, &appErr) {
		return e.code == appErr.code
	}
	return false
}

// WithMessage returns a new AppError with the same code but a different message.
func (e *AppError) WithMessage(message string) *AppError {
	return &AppError{
		code:    e.code,
		message: message,
		cause:   e.cause,
	}
}

// WithCause returns a new AppError with the same code and message but wrapping
// a different cause.
func (e *AppError) WithCause(cause error) *AppError {
	return &AppError{
		code:    e.code,
		message: e.message,
		cause:   cause,
	}
}

// ErrorResponse represents the JSON structure for error responses.
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail contains the error information in the response.
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ToResponse converts an AppError to an ErrorResponse suitable for JSON serialization.
// Internal error details are never exposed to clients.
func (e *AppError) ToResponse() ErrorResponse {
	message := e.message
	// Never expose internal error details to clients.
	if e.code == CodeInternalError {
		message = "an internal error occurred"
	}
	return ErrorResponse{
		Error: ErrorDetail{
			Code:    e.code.String(),
			Message: message,
		},
	}
}

// WriteJSON writes the error as a JSON response to the provided http.ResponseWriter.
// It sets the Content-Type header and writes the appropriate HTTP status code.
func (e *AppError) WriteJSON(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(e.HTTPStatus())
	return json.NewEncoder(w).Encode(e.ToResponse())
}

// Constructors for common error types.

// ValidationError creates a new validation error with the given message.
func ValidationError(message string) *AppError {
	return New(CodeValidationError, message)
}

// ValidationErrorf creates a new validation error with a formatted message.
func ValidationErrorf(format string, args ...any) *AppError {
	return New(CodeValidationError, fmt.Sprintf(format, args...))
}

// InvalidCredentials creates a new invalid credentials error.
func InvalidCredentials(message string) *AppError {
	return New(CodeInvalidCredentials, message)
}

// TokenExpired creates a new token expired error.
func TokenExpired(message string) *AppError {
	return New(CodeTokenExpired, message)
}

// TokenInvalid creates a new token invalid error.
func TokenInvalid(message string) *AppError {
	return New(CodeTokenInvalid, message)
}

// Forbidden creates a new forbidden error with the given message.
func Forbidden(message string) *AppError {
	return New(CodeForbidden, message)
}

// NotFound creates a new not found error with the given message.
func NotFound(message string) *AppError {
	return New(CodeNotFound, message)
}

// NotFoundf creates a new not found error with a formatted message.
func NotFoundf(format string, args ...any) *AppError {
	return New(CodeNotFound, fmt.Sprintf(format, args...))
}

// Conflict creates a new conflict error with the given message.
func Conflict(message string) *AppError {
	return New(CodeConflict, message)
}

// Conflictf creates a new conflict error with a formatted message.
func Conflictf(format string, args ...any) *AppError {
	return New(CodeConflict, fmt.Sprintf(format, args...))
}

// RateLimited creates a new rate limited error.
func RateLimited(message string) *AppError {
	return New(CodeRateLimited, message)
}

// InternalError creates a new internal error with the given message.
// The message is logged server-side but never exposed to clients.
func InternalError(message string) *AppError {
	return New(CodeInternalError, message)
}

// InternalErrorf creates a new internal error with a formatted message.
func InternalErrorf(format string, args ...any) *AppError {
	return New(CodeInternalError, fmt.Sprintf(format, args...))
}

// InternalErrorWrap creates a new internal error wrapping an existing error.
// The wrapped error is logged server-side but never exposed to clients.
func InternalErrorWrap(message string, cause error) *AppError {
	return Wrap(CodeInternalError, message, cause)
}

// ServiceUnavailable creates a new service unavailable error.
func ServiceUnavailable(message string) *AppError {
	return New(CodeServiceUnavailable, message)
}

// ServiceUnavailablef creates a new service unavailable error with a formatted message.
func ServiceUnavailablef(format string, args ...any) *AppError {
	return New(CodeServiceUnavailable, fmt.Sprintf(format, args...))
}

// Helper functions for error checking.

// IsAppError checks if the given error is an AppError.
func IsAppError(err error) bool {
	var appErr *AppError
	return errors.As(err, &appErr)
}

// AsAppError attempts to extract an AppError from the given error.
// Returns nil if the error is not an AppError.
func AsAppError(err error) *AppError {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr
	}
	return nil
}

// GetCode returns the error code from an error if it's an AppError,
// or CodeInternalError otherwise.
func GetCode(err error) Code {
	if appErr := AsAppError(err); appErr != nil {
		return appErr.Code()
	}
	return CodeInternalError
}

// GetHTTPStatus returns the HTTP status code from an error if it's an AppError,
// or 500 Internal Server Error otherwise.
func GetHTTPStatus(err error) int {
	if appErr := AsAppError(err); appErr != nil {
		return appErr.HTTPStatus()
	}
	return http.StatusInternalServerError
}

// FromError converts any error to an AppError.
// If the error is already an AppError, it is returned as-is.
// Otherwise, a new InternalError wrapping the original error is created.
func FromError(err error) *AppError {
	if appErr := AsAppError(err); appErr != nil {
		return appErr
	}
	return InternalErrorWrap("unexpected error", err)
}

// IsCode checks if the given error is an AppError with the specified code.
func IsCode(err error, code Code) bool {
	if appErr := AsAppError(err); appErr != nil {
		return appErr.Code() == code
	}
	return false
}

// IsValidationError checks if the error is a validation error.
func IsValidationError(err error) bool {
	return IsCode(err, CodeValidationError)
}

// IsNotFound checks if the error is a not found error.
func IsNotFound(err error) bool {
	return IsCode(err, CodeNotFound)
}

// IsForbidden checks if the error is a forbidden error.
func IsForbidden(err error) bool {
	return IsCode(err, CodeForbidden)
}

// IsUnauthorized checks if the error is an unauthorized error
// (invalid credentials, token expired, or token invalid).
func IsUnauthorized(err error) bool {
	code := GetCode(err)
	return code == CodeInvalidCredentials || code == CodeTokenExpired || code == CodeTokenInvalid
}

// IsConflict checks if the error is a conflict error.
func IsConflict(err error) bool {
	return IsCode(err, CodeConflict)
}

// IsInternalError checks if the error is an internal error.
func IsInternalError(err error) bool {
	return IsCode(err, CodeInternalError)
}

// IsServiceUnavailable checks if the error is a service unavailable error.
func IsServiceUnavailable(err error) bool {
	return IsCode(err, CodeServiceUnavailable)
}

// IsRateLimited checks if the error is a rate limited error.
func IsRateLimited(err error) bool {
	return IsCode(err, CodeRateLimited)
}
