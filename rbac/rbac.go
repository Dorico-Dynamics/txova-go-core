// Package rbac provides role-based access control for the Txova platform.
// It defines roles, permissions, and provides functions for permission checking.
package rbac

import (
	"context"
	"log/slog"
	"sync"

	txcontext "github.com/Dorico-Dynamics/txova-go-core/context"
	"github.com/Dorico-Dynamics/txova-go-core/errors"
)

// Role represents a user role in the system.
type Role string

// Standard roles for the Txova platform.
const (
	RoleRider      Role = "rider"
	RoleDriver     Role = "driver"
	RoleSupport    Role = "support"
	RoleOps        Role = "ops"
	RoleAdmin      Role = "admin"
	RoleSuperAdmin Role = "super_admin"
)

// AllRoles returns all defined roles.
func AllRoles() []Role {
	return []Role{
		RoleRider,
		RoleDriver,
		RoleSupport,
		RoleOps,
		RoleAdmin,
		RoleSuperAdmin,
	}
}

// Valid returns true if the role is a valid defined role.
func (r Role) Valid() bool {
	switch r {
	case RoleRider, RoleDriver, RoleSupport, RoleOps, RoleAdmin, RoleSuperAdmin:
		return true
	default:
		return false
	}
}

// String returns the string representation of the role.
func (r Role) String() string {
	return string(r)
}

// Permission represents an action that can be performed in the system.
type Permission string

// Standard permissions for the Txova platform.
const (
	// User permissions.
	PermUsersRead  Permission = "users:read"
	PermUsersWrite Permission = "users:write"

	// Driver permissions.
	PermDriversRead   Permission = "drivers:read"
	PermDriversWrite  Permission = "drivers:write"
	PermDriversVerify Permission = "drivers:verify"

	// Ride permissions.
	PermRidesRead   Permission = "rides:read"
	PermRidesCancel Permission = "rides:cancel"

	// Payment permissions.
	PermPaymentsRead   Permission = "payments:read"
	PermPaymentsRefund Permission = "payments:refund"

	// Config permissions.
	PermConfigRead  Permission = "config:read"
	PermConfigWrite Permission = "config:write"
)

// AllPermissions returns all defined permissions.
func AllPermissions() []Permission {
	return []Permission{
		PermUsersRead,
		PermUsersWrite,
		PermDriversRead,
		PermDriversWrite,
		PermDriversVerify,
		PermRidesRead,
		PermRidesCancel,
		PermPaymentsRead,
		PermPaymentsRefund,
		PermConfigRead,
		PermConfigWrite,
	}
}

// Valid returns true if the permission is a valid defined permission.
func (p Permission) Valid() bool {
	for _, perm := range AllPermissions() {
		if p == perm {
			return true
		}
	}
	return false
}

// String returns the string representation of the permission.
func (p Permission) String() string {
	return string(p)
}

// defaultRolePermissions defines the default permissions for each role.
// Permissions are additive - a role grants the listed permissions.
var defaultRolePermissions = map[Role][]Permission{
	RoleRider: {
		PermUsersRead,
		PermRidesRead,
		PermPaymentsRead,
	},
	RoleDriver: {
		PermUsersRead,
		PermDriversRead,
		PermRidesRead,
		PermPaymentsRead,
	},
	RoleSupport: {
		PermUsersRead,
		PermDriversRead,
		PermRidesRead,
		PermRidesCancel,
		PermPaymentsRead,
	},
	RoleOps: {
		PermUsersRead,
		PermUsersWrite,
		PermDriversRead,
		PermDriversWrite,
		PermDriversVerify,
		PermRidesRead,
		PermRidesCancel,
		PermPaymentsRead,
		PermPaymentsRefund,
	},
	RoleAdmin: {
		PermUsersRead,
		PermUsersWrite,
		PermDriversRead,
		PermDriversWrite,
		PermDriversVerify,
		PermRidesRead,
		PermRidesCancel,
		PermPaymentsRead,
		PermPaymentsRefund,
		PermConfigRead,
	},
	RoleSuperAdmin: {
		PermUsersRead,
		PermUsersWrite,
		PermDriversRead,
		PermDriversWrite,
		PermDriversVerify,
		PermRidesRead,
		PermRidesCancel,
		PermPaymentsRead,
		PermPaymentsRefund,
		PermConfigRead,
		PermConfigWrite,
	},
}

// Manager handles role-based access control with in-memory caching.
type Manager struct {
	mu              sync.RWMutex
	rolePermissions map[Role]map[Permission]bool
	logger          *slog.Logger
}

// NewManager creates a new RBAC manager with default role-permission mappings.
func NewManager(logger *slog.Logger) *Manager {
	m := &Manager{
		rolePermissions: make(map[Role]map[Permission]bool),
		logger:          logger,
	}

	// Initialize with default permissions.
	for role, perms := range defaultRolePermissions {
		m.rolePermissions[role] = make(map[Permission]bool)
		for _, perm := range perms {
			m.rolePermissions[role][perm] = true
		}
	}

	return m
}

// HasPermission checks if a role has a specific permission.
func (m *Manager) HasPermission(role Role, permission Permission) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	perms, ok := m.rolePermissions[role]
	if !ok {
		return false
	}
	return perms[permission]
}

// HasAnyPermission checks if a role has any of the specified permissions.
func (m *Manager) HasAnyPermission(role Role, permissions ...Permission) bool {
	for _, perm := range permissions {
		if m.HasPermission(role, perm) {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if a role has all of the specified permissions.
func (m *Manager) HasAllPermissions(role Role, permissions ...Permission) bool {
	for _, perm := range permissions {
		if !m.HasPermission(role, perm) {
			return false
		}
	}
	return true
}

// GetPermissions returns all permissions for a role.
func (m *Manager) GetPermissions(role Role) []Permission {
	m.mu.RLock()
	defer m.mu.RUnlock()

	perms, ok := m.rolePermissions[role]
	if !ok {
		return nil
	}

	result := make([]Permission, 0, len(perms))
	for perm := range perms {
		result = append(result, perm)
	}
	return result
}

// RolesHavePermission checks if any of the given roles has the permission.
func (m *Manager) RolesHavePermission(roles []string, permission Permission) bool {
	for _, roleStr := range roles {
		role := Role(roleStr)
		if m.HasPermission(role, permission) {
			return true
		}
	}
	return false
}

// RolesHaveAnyPermission checks if any of the given roles has any of the permissions.
func (m *Manager) RolesHaveAnyPermission(roles []string, permissions ...Permission) bool {
	for _, roleStr := range roles {
		role := Role(roleStr)
		if m.HasAnyPermission(role, permissions...) {
			return true
		}
	}
	return false
}

// RolesHaveAllPermissions checks if the given roles together have all permissions.
func (m *Manager) RolesHaveAllPermissions(roles []string, permissions ...Permission) bool {
	for _, perm := range permissions {
		hasPermission := false
		for _, roleStr := range roles {
			role := Role(roleStr)
			if m.HasPermission(role, perm) {
				hasPermission = true
				break
			}
		}
		if !hasPermission {
			return false
		}
	}
	return true
}

// CheckPermission checks if the user in the context has the required permission.
// Returns an error if the permission is denied.
func (m *Manager) CheckPermission(ctx context.Context, permission Permission) error {
	claims := txcontext.Claims(ctx)
	if claims.IsZero() {
		m.logDenial(ctx, "", permission, "no authenticated user")
		return errors.Forbidden("authentication required")
	}

	if !m.RolesHavePermission(claims.Roles, permission) {
		m.logDenial(ctx, claims.UserID.String(), permission, "insufficient permissions")
		return errors.Forbidden("permission denied")
	}

	return nil
}

// CheckAnyPermission checks if the user has any of the required permissions.
func (m *Manager) CheckAnyPermission(ctx context.Context, permissions ...Permission) error {
	claims := txcontext.Claims(ctx)
	if claims.IsZero() {
		m.logDenial(ctx, "", permissions[0], "no authenticated user")
		return errors.Forbidden("authentication required")
	}

	if !m.RolesHaveAnyPermission(claims.Roles, permissions...) {
		m.logDenial(ctx, claims.UserID.String(), permissions[0], "insufficient permissions")
		return errors.Forbidden("permission denied")
	}

	return nil
}

// CheckAllPermissions checks if the user has all of the required permissions.
func (m *Manager) CheckAllPermissions(ctx context.Context, permissions ...Permission) error {
	claims := txcontext.Claims(ctx)
	if claims.IsZero() {
		m.logDenial(ctx, "", permissions[0], "no authenticated user")
		return errors.Forbidden("authentication required")
	}

	if !m.RolesHaveAllPermissions(claims.Roles, permissions...) {
		m.logDenial(ctx, claims.UserID.String(), permissions[0], "insufficient permissions")
		return errors.Forbidden("permission denied")
	}

	return nil
}

// RequireRole checks if the user has the specified role.
func (m *Manager) RequireRole(ctx context.Context, role Role) error {
	claims := txcontext.Claims(ctx)
	if claims.IsZero() {
		m.logDenial(ctx, "", Permission("role:"+role.String()), "no authenticated user")
		return errors.Forbidden("authentication required")
	}

	for _, r := range claims.Roles {
		if Role(r) == role {
			return nil
		}
	}

	m.logDenial(ctx, claims.UserID.String(), Permission("role:"+role.String()), "role not assigned")
	return errors.Forbidden("permission denied")
}

// RequireAnyRole checks if the user has any of the specified roles.
func (m *Manager) RequireAnyRole(ctx context.Context, roles ...Role) error {
	claims := txcontext.Claims(ctx)
	if claims.IsZero() {
		return errors.Forbidden("authentication required")
	}

	for _, userRole := range claims.Roles {
		for _, requiredRole := range roles {
			if Role(userRole) == requiredRole {
				return nil
			}
		}
	}

	m.logDenial(ctx, claims.UserID.String(), Permission("role:any"), "required role not assigned")
	return errors.Forbidden("permission denied")
}

// logDenial logs a permission denial.
func (m *Manager) logDenial(ctx context.Context, userID string, permission Permission, reason string) {
	if m.logger == nil {
		return
	}

	attrs := []any{
		"permission", permission.String(),
		"reason", reason,
	}

	if userID != "" {
		attrs = append(attrs, "user_id", userID)
	}

	if requestID := txcontext.RequestID(ctx); requestID != "" {
		attrs = append(attrs, "request_id", requestID)
	}

	m.logger.Warn("permission denied", attrs...)
}

// SetPermissions replaces the permissions for a role.
// This can be used to customize role permissions at runtime.
func (m *Manager) SetPermissions(role Role, permissions []Permission) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.rolePermissions[role] = make(map[Permission]bool)
	for _, perm := range permissions {
		m.rolePermissions[role][perm] = true
	}
}

// AddPermission adds a permission to a role.
func (m *Manager) AddPermission(role Role, permission Permission) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.rolePermissions[role] == nil {
		m.rolePermissions[role] = make(map[Permission]bool)
	}
	m.rolePermissions[role][permission] = true
}

// RemovePermission removes a permission from a role.
func (m *Manager) RemovePermission(role Role, permission Permission) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.rolePermissions[role] != nil {
		delete(m.rolePermissions[role], permission)
	}
}

// Checker provides a simplified interface for permission checking.
// It wraps a Manager and provides convenience methods.
type Checker struct {
	manager *Manager
}

// NewChecker creates a new permission checker.
func NewChecker(manager *Manager) *Checker {
	return &Checker{manager: manager}
}

// Can checks if the context user can perform the given permission.
func (c *Checker) Can(ctx context.Context, permission Permission) bool {
	return c.manager.CheckPermission(ctx, permission) == nil
}

// CanAny checks if the context user can perform any of the given permissions.
func (c *Checker) CanAny(ctx context.Context, permissions ...Permission) bool {
	return c.manager.CheckAnyPermission(ctx, permissions...) == nil
}

// CanAll checks if the context user can perform all of the given permissions.
func (c *Checker) CanAll(ctx context.Context, permissions ...Permission) bool {
	return c.manager.CheckAllPermissions(ctx, permissions...) == nil
}

// IsRole checks if the context user has the specified role.
func (c *Checker) IsRole(ctx context.Context, role Role) bool {
	return c.manager.RequireRole(ctx, role) == nil
}

// IsAnyRole checks if the context user has any of the specified roles.
func (c *Checker) IsAnyRole(ctx context.Context, roles ...Role) bool {
	return c.manager.RequireAnyRole(ctx, roles...) == nil
}
