// Package context provides utilities for managing request-scoped values
// in the context, including request IDs, user claims, and correlation IDs.
package context

import (
	"context"
	"time"

	"github.com/Dorico-Dynamics/txova-go-types/enums"
	"github.com/Dorico-Dynamics/txova-go-types/ids"
)

// contextKey is an unexported type for context keys to prevent collisions.
type contextKey int

const (
	requestIDKey contextKey = iota
	correlationIDKey
	userClaimsKey
)

// RequestID retrieves the request ID from the context.
// Returns an empty string if no request ID is set.
func RequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

// WithRequestID returns a new context with the given request ID.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// CorrelationID retrieves the correlation ID from the context.
// Returns an empty string if no correlation ID is set.
func CorrelationID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(correlationIDKey).(string); ok {
		return id
	}
	return ""
}

// WithCorrelationID returns a new context with the given correlation ID.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationIDKey, id)
}

// UserClaims represents the authenticated user's claims extracted from a JWT.
type UserClaims struct {
	// UserID is the unique identifier of the user (sub claim).
	UserID ids.UserID
	// UserType indicates the type of user (rider, driver, admin).
	UserType enums.UserType
	// Roles contains the user's permission roles.
	Roles []string
	// TokenID is the unique identifier of the token (jti claim).
	TokenID string
	// IssuedAt is when the token was issued.
	IssuedAt time.Time
	// ExpiresAt is when the token expires.
	ExpiresAt time.Time
}

// IsZero returns true if the claims are empty/unset.
func (c UserClaims) IsZero() bool {
	return c.UserID.IsZero()
}

// HasRole checks if the user has the specified role.
func (c UserClaims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole checks if the user has any of the specified roles.
func (c UserClaims) HasAnyRole(roles ...string) bool {
	for _, role := range roles {
		if c.HasRole(role) {
			return true
		}
	}
	return false
}

// HasAllRoles checks if the user has all of the specified roles.
func (c UserClaims) HasAllRoles(roles ...string) bool {
	for _, role := range roles {
		if !c.HasRole(role) {
			return false
		}
	}
	return true
}

// Claims retrieves the user claims from the context.
// Returns a zero UserClaims if no claims are set.
func Claims(ctx context.Context) UserClaims {
	if ctx == nil {
		return UserClaims{}
	}
	if claims, ok := ctx.Value(userClaimsKey).(UserClaims); ok {
		return claims
	}
	return UserClaims{}
}

// WithClaims returns a new context with the given user claims.
func WithClaims(ctx context.Context, claims UserClaims) context.Context {
	return context.WithValue(ctx, userClaimsKey, claims)
}

// UserID retrieves the user ID from the claims in the context.
// Returns a zero UserID if no claims are set.
func UserID(ctx context.Context) ids.UserID {
	return Claims(ctx).UserID
}

// UserIDString retrieves the user ID as a string from the claims in the context.
// Returns an empty string if no claims are set.
func UserIDString(ctx context.Context) string {
	uid := Claims(ctx).UserID
	if uid.IsZero() {
		return ""
	}
	return uid.String()
}

// UserType retrieves the user type from the claims in the context.
// Returns an empty UserType if no claims are set.
func UserType(ctx context.Context) enums.UserType {
	return Claims(ctx).UserType
}

// IsAuthenticated returns true if the context contains valid user claims.
func IsAuthenticated(ctx context.Context) bool {
	return !Claims(ctx).IsZero()
}

// WithTimeout returns a new context with the given timeout.
// This is a convenience wrapper around context.WithTimeout.
func WithTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, timeout)
}

// WithDeadline returns a new context with the given deadline.
// This is a convenience wrapper around context.WithDeadline.
func WithDeadline(ctx context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
	return context.WithDeadline(ctx, deadline)
}

// HTTP header names for propagating context values.
const (
	// HeaderRequestID is the HTTP header for request ID propagation.
	HeaderRequestID = "X-Request-ID"
	// HeaderCorrelationID is the HTTP header for correlation ID propagation.
	HeaderCorrelationID = "X-Correlation-ID"
)
