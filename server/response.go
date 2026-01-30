package server

import (
	"encoding/json"
	"net/http"
	"time"

	txcontext "github.com/Dorico-Dynamics/txova-go-core/context"
	"github.com/Dorico-Dynamics/txova-go-core/errors"
)

// Response represents a standard API response envelope.
type Response struct {
	Data  any            `json:"data,omitempty"`
	Error *ErrorResponse `json:"error,omitempty"`
	Meta  *Meta          `json:"meta,omitempty"`
}

// ErrorResponse represents the error portion of the response.
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Meta contains metadata about the response.
type Meta struct {
	RequestID string `json:"request_id,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
	// Pagination fields (optional).
	Page       int `json:"page,omitempty"`
	PerPage    int `json:"per_page,omitempty"`
	Total      int `json:"total,omitempty"`
	TotalPages int `json:"total_pages,omitempty"`
}

// PaginationMeta creates pagination metadata.
type PaginationMeta struct {
	Page       int
	PerPage    int
	Total      int
	TotalPages int
}

// WriteJSON writes a successful JSON response with the standard envelope.
func WriteJSON(w http.ResponseWriter, r *http.Request, status int, data any) {
	resp := Response{
		Data: data,
		Meta: &Meta{
			RequestID: txcontext.RequestID(r.Context()),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// WriteJSONWithPagination writes a successful JSON response with pagination metadata.
func WriteJSONWithPagination(w http.ResponseWriter, r *http.Request, status int, data any, pagination PaginationMeta) {
	resp := Response{
		Data: data,
		Meta: &Meta{
			RequestID:  txcontext.RequestID(r.Context()),
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
			Page:       pagination.Page,
			PerPage:    pagination.PerPage,
			Total:      pagination.Total,
			TotalPages: pagination.TotalPages,
		},
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// WriteError writes an error response with the standard envelope.
func WriteError(w http.ResponseWriter, status int, code string, message string) {
	resp := Response{
		Error: &ErrorResponse{
			Code:    code,
			Message: message,
		},
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// WriteAppError writes an AppError as a JSON response.
func WriteAppError(w http.ResponseWriter, r *http.Request, err *errors.AppError) {
	resp := Response{
		Error: &ErrorResponse{
			Code:    err.Code().String(),
			Message: safeErrorMessage(err),
		},
		Meta: &Meta{
			RequestID: txcontext.RequestID(r.Context()),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(err.HTTPStatus())
	_ = json.NewEncoder(w).Encode(resp)
}

// HandleError writes any error as a JSON response.
// If the error is an AppError, it uses its code and status.
// Otherwise, it returns a generic internal error.
func HandleError(w http.ResponseWriter, r *http.Request, err error) {
	if appErr := errors.AsAppError(err); appErr != nil {
		WriteAppError(w, r, appErr)
		return
	}

	// Generic internal error - don't expose details.
	WriteAppError(w, r, errors.InternalError("an internal error occurred"))
}

// safeErrorMessage returns the error message, sanitizing internal errors.
func safeErrorMessage(err *errors.AppError) string {
	// Never expose internal error details to clients.
	if err.Code() == errors.CodeInternalError {
		return "an internal error occurred"
	}
	return err.Message()
}

// OK writes a 200 OK response with data.
func OK(w http.ResponseWriter, r *http.Request, data any) {
	WriteJSON(w, r, http.StatusOK, data)
}

// Created writes a 201 Created response with data.
func Created(w http.ResponseWriter, r *http.Request, data any) {
	WriteJSON(w, r, http.StatusCreated, data)
}

// NoContent writes a 204 No Content response.
func NoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// BadRequest writes a 400 Bad Request error response.
func BadRequest(w http.ResponseWriter, r *http.Request, message string) {
	WriteAppError(w, r, errors.ValidationError(message))
}

// Unauthorized writes a 401 Unauthorized error response.
func Unauthorized(w http.ResponseWriter, r *http.Request, message string) {
	WriteAppError(w, r, errors.InvalidCredentials(message))
}

// Forbidden writes a 403 Forbidden error response.
func Forbidden(w http.ResponseWriter, r *http.Request, message string) {
	WriteAppError(w, r, errors.Forbidden(message))
}

// NotFound writes a 404 Not Found error response.
func NotFound(w http.ResponseWriter, r *http.Request, message string) {
	WriteAppError(w, r, errors.NotFound(message))
}

// Conflict writes a 409 Conflict error response.
func Conflict(w http.ResponseWriter, r *http.Request, message string) {
	WriteAppError(w, r, errors.Conflict(message))
}

// InternalError writes a 500 Internal Server Error response.
func InternalError(w http.ResponseWriter, r *http.Request) {
	WriteAppError(w, r, errors.InternalError("an internal error occurred"))
}

// DecodeJSON decodes a JSON request body into the provided struct.
// Returns an error if decoding fails.
func DecodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return errors.ValidationError("request body is required")
	}

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(v); err != nil {
		return errors.ValidationError("invalid JSON: " + err.Error())
	}

	return nil
}
