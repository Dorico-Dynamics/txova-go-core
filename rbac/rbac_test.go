package rbac

import (
	"context"
	"testing"

	txcontext "github.com/Dorico-Dynamics/txova-go-core/context"
	"github.com/Dorico-Dynamics/txova-go-core/errors"
)

func TestRole_Valid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		role  Role
		valid bool
	}{
		{RoleRider, true},
		{RoleDriver, true},
		{RoleSupport, true},
		{RoleOps, true},
		{RoleAdmin, true},
		{RoleSuperAdmin, true},
		{Role("invalid"), false},
		{Role(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			t.Parallel()
			if got := tt.role.Valid(); got != tt.valid {
				t.Errorf("Role(%q).Valid() = %v, want %v", tt.role, got, tt.valid)
			}
		})
	}
}

func TestRole_String(t *testing.T) {
	t.Parallel()

	if got := RoleRider.String(); got != "rider" {
		t.Errorf("RoleRider.String() = %v, want rider", got)
	}
}

func TestPermission_Valid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		perm  Permission
		valid bool
	}{
		{PermUsersRead, true},
		{PermUsersWrite, true},
		{PermDriversRead, true},
		{PermDriversWrite, true},
		{PermDriversVerify, true},
		{PermRidesRead, true},
		{PermRidesCancel, true},
		{PermPaymentsRead, true},
		{PermPaymentsRefund, true},
		{PermConfigRead, true},
		{PermConfigWrite, true},
		{Permission("invalid"), false},
		{Permission(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.perm), func(t *testing.T) {
			t.Parallel()
			if got := tt.perm.Valid(); got != tt.valid {
				t.Errorf("Permission(%q).Valid() = %v, want %v", tt.perm, got, tt.valid)
			}
		})
	}
}

func TestPermission_String(t *testing.T) {
	t.Parallel()

	if got := PermUsersRead.String(); got != "users:read" {
		t.Errorf("PermUsersRead.String() = %v, want users:read", got)
	}
}

func TestAllRoles(t *testing.T) {
	t.Parallel()

	roles := AllRoles()
	if len(roles) != 6 {
		t.Errorf("AllRoles() length = %v, want 6", len(roles))
	}

	expected := []Role{RoleRider, RoleDriver, RoleSupport, RoleOps, RoleAdmin, RoleSuperAdmin}
	for _, exp := range expected {
		found := false
		for _, r := range roles {
			if r == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("AllRoles() missing %v", exp)
		}
	}
}

func TestAllPermissions(t *testing.T) {
	t.Parallel()

	perms := AllPermissions()
	if len(perms) != 11 {
		t.Errorf("AllPermissions() length = %v, want 11", len(perms))
	}
}

func TestNewManager(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)
	if m == nil {
		t.Fatal("NewManager() returned nil")
	}

	// Verify default permissions are set.
	if !m.HasPermission(RoleRider, PermUsersRead) {
		t.Error("rider should have users:read permission")
	}
	if m.HasPermission(RoleRider, PermConfigWrite) {
		t.Error("rider should not have config:write permission")
	}
}

func TestManager_HasPermission(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)

	tests := []struct {
		role       Role
		permission Permission
		expected   bool
	}{
		{RoleRider, PermUsersRead, true},
		{RoleRider, PermRidesRead, true},
		{RoleRider, PermConfigWrite, false},
		{RoleDriver, PermDriversRead, true},
		{RoleDriver, PermDriversVerify, false},
		{RoleSupport, PermRidesCancel, true},
		{RoleOps, PermPaymentsRefund, true},
		{RoleAdmin, PermConfigRead, true},
		{RoleAdmin, PermConfigWrite, false},
		{RoleSuperAdmin, PermConfigWrite, true},
		{Role("invalid"), PermUsersRead, false},
	}

	for _, tt := range tests {
		name := string(tt.role) + "-" + string(tt.permission)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := m.HasPermission(tt.role, tt.permission); got != tt.expected {
				t.Errorf("HasPermission(%v, %v) = %v, want %v", tt.role, tt.permission, got, tt.expected)
			}
		})
	}
}

func TestManager_HasAnyPermission(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)

	tests := []struct {
		name        string
		role        Role
		permissions []Permission
		expected    bool
	}{
		{"rider has any of users:read, config:write", RoleRider, []Permission{PermUsersRead, PermConfigWrite}, true},
		{"rider has none of config:read, config:write", RoleRider, []Permission{PermConfigRead, PermConfigWrite}, false},
		{"admin has any of config:read, config:write", RoleAdmin, []Permission{PermConfigRead, PermConfigWrite}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := m.HasAnyPermission(tt.role, tt.permissions...); got != tt.expected {
				t.Errorf("HasAnyPermission() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestManager_HasAllPermissions(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)

	tests := []struct {
		name        string
		role        Role
		permissions []Permission
		expected    bool
	}{
		{"rider has all of users:read, rides:read", RoleRider, []Permission{PermUsersRead, PermRidesRead}, true},
		{"rider has all of users:read, config:write", RoleRider, []Permission{PermUsersRead, PermConfigWrite}, false},
		{"super_admin has all permissions", RoleSuperAdmin, AllPermissions(), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := m.HasAllPermissions(tt.role, tt.permissions...); got != tt.expected {
				t.Errorf("HasAllPermissions() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestManager_GetPermissions(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)

	perms := m.GetPermissions(RoleRider)
	if len(perms) != 3 {
		t.Errorf("GetPermissions(rider) length = %v, want 3", len(perms))
	}

	// Invalid role.
	perms = m.GetPermissions(Role("invalid"))
	if perms != nil {
		t.Errorf("GetPermissions(invalid) = %v, want nil", perms)
	}
}

func TestManager_RolesHavePermission(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)

	tests := []struct {
		name       string
		roles      []string
		permission Permission
		expected   bool
	}{
		{"single role with permission", []string{"rider"}, PermUsersRead, true},
		{"single role without permission", []string{"rider"}, PermConfigWrite, false},
		{"multiple roles, one has permission", []string{"rider", "admin"}, PermConfigRead, true},
		{"empty roles", []string{}, PermUsersRead, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := m.RolesHavePermission(tt.roles, tt.permission); got != tt.expected {
				t.Errorf("RolesHavePermission() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestManager_RolesHaveAnyPermission(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)

	tests := []struct {
		name        string
		roles       []string
		permissions []Permission
		expected    bool
	}{
		{"rider has users:read", []string{"rider"}, []Permission{PermConfigWrite, PermUsersRead}, true},
		{"rider has none", []string{"rider"}, []Permission{PermConfigWrite, PermConfigRead}, false},
		{"combined roles have one", []string{"rider", "admin"}, []Permission{PermConfigRead}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := m.RolesHaveAnyPermission(tt.roles, tt.permissions...); got != tt.expected {
				t.Errorf("RolesHaveAnyPermission() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestManager_RolesHaveAllPermissions(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)

	tests := []struct {
		name        string
		roles       []string
		permissions []Permission
		expected    bool
	}{
		{"rider has all basic", []string{"rider"}, []Permission{PermUsersRead, PermRidesRead}, true},
		{"rider missing config:read", []string{"rider"}, []Permission{PermUsersRead, PermConfigRead}, false},
		{"combined roles have all", []string{"rider", "admin"}, []Permission{PermUsersRead, PermConfigRead}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := m.RolesHaveAllPermissions(tt.roles, tt.permissions...); got != tt.expected {
				t.Errorf("RolesHaveAllPermissions() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestManager_CheckPermission(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)

	t.Run("authenticated with permission", func(t *testing.T) {
		t.Parallel()
		ctx := txcontext.WithClaims(context.Background(), txcontext.UserClaims{
			UserID: "user-123",
			Roles:  []string{"rider"},
		})
		err := m.CheckPermission(ctx, PermUsersRead)
		if err != nil {
			t.Errorf("CheckPermission() error = %v", err)
		}
	})

	t.Run("authenticated without permission", func(t *testing.T) {
		t.Parallel()
		ctx := txcontext.WithClaims(context.Background(), txcontext.UserClaims{
			UserID: "user-123",
			Roles:  []string{"rider"},
		})
		err := m.CheckPermission(ctx, PermConfigWrite)
		if err == nil {
			t.Fatal("CheckPermission() should fail without permission")
		}
		if !errors.IsForbidden(err) {
			t.Errorf("error should be forbidden, got: %v", err)
		}
	})

	t.Run("unauthenticated", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		err := m.CheckPermission(ctx, PermUsersRead)
		if err == nil {
			t.Fatal("CheckPermission() should fail when unauthenticated")
		}
		if !errors.IsForbidden(err) {
			t.Errorf("error should be forbidden, got: %v", err)
		}
	})
}

func TestManager_CheckAnyPermission(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)

	t.Run("has one of the permissions", func(t *testing.T) {
		t.Parallel()
		ctx := txcontext.WithClaims(context.Background(), txcontext.UserClaims{
			UserID: "user-123",
			Roles:  []string{"rider"},
		})
		err := m.CheckAnyPermission(ctx, PermConfigWrite, PermUsersRead)
		if err != nil {
			t.Errorf("CheckAnyPermission() error = %v", err)
		}
	})

	t.Run("has none of the permissions", func(t *testing.T) {
		t.Parallel()
		ctx := txcontext.WithClaims(context.Background(), txcontext.UserClaims{
			UserID: "user-123",
			Roles:  []string{"rider"},
		})
		err := m.CheckAnyPermission(ctx, PermConfigWrite, PermConfigRead)
		if err == nil {
			t.Fatal("CheckAnyPermission() should fail")
		}
	})
}

func TestManager_CheckAllPermissions(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)

	t.Run("has all permissions", func(t *testing.T) {
		t.Parallel()
		ctx := txcontext.WithClaims(context.Background(), txcontext.UserClaims{
			UserID: "user-123",
			Roles:  []string{"rider"},
		})
		err := m.CheckAllPermissions(ctx, PermUsersRead, PermRidesRead)
		if err != nil {
			t.Errorf("CheckAllPermissions() error = %v", err)
		}
	})

	t.Run("missing one permission", func(t *testing.T) {
		t.Parallel()
		ctx := txcontext.WithClaims(context.Background(), txcontext.UserClaims{
			UserID: "user-123",
			Roles:  []string{"rider"},
		})
		err := m.CheckAllPermissions(ctx, PermUsersRead, PermConfigRead)
		if err == nil {
			t.Fatal("CheckAllPermissions() should fail")
		}
	})
}

func TestManager_RequireRole(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)

	t.Run("has required role", func(t *testing.T) {
		t.Parallel()
		ctx := txcontext.WithClaims(context.Background(), txcontext.UserClaims{
			UserID: "user-123",
			Roles:  []string{"rider", "driver"},
		})
		err := m.RequireRole(ctx, RoleDriver)
		if err != nil {
			t.Errorf("RequireRole() error = %v", err)
		}
	})

	t.Run("missing required role", func(t *testing.T) {
		t.Parallel()
		ctx := txcontext.WithClaims(context.Background(), txcontext.UserClaims{
			UserID: "user-123",
			Roles:  []string{"rider"},
		})
		err := m.RequireRole(ctx, RoleAdmin)
		if err == nil {
			t.Fatal("RequireRole() should fail")
		}
	})

	t.Run("unauthenticated", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		err := m.RequireRole(ctx, RoleRider)
		if err == nil {
			t.Fatal("RequireRole() should fail when unauthenticated")
		}
	})
}

func TestManager_RequireAnyRole(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)

	t.Run("has one of the roles", func(t *testing.T) {
		t.Parallel()
		ctx := txcontext.WithClaims(context.Background(), txcontext.UserClaims{
			UserID: "user-123",
			Roles:  []string{"rider"},
		})
		err := m.RequireAnyRole(ctx, RoleAdmin, RoleRider)
		if err != nil {
			t.Errorf("RequireAnyRole() error = %v", err)
		}
	})

	t.Run("has none of the roles", func(t *testing.T) {
		t.Parallel()
		ctx := txcontext.WithClaims(context.Background(), txcontext.UserClaims{
			UserID: "user-123",
			Roles:  []string{"rider"},
		})
		err := m.RequireAnyRole(ctx, RoleAdmin, RoleSuperAdmin)
		if err == nil {
			t.Fatal("RequireAnyRole() should fail")
		}
	})
}

func TestManager_SetPermissions(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)

	// Verify rider has default permissions.
	if !m.HasPermission(RoleRider, PermUsersRead) {
		t.Fatal("rider should have users:read by default")
	}

	// Replace permissions.
	m.SetPermissions(RoleRider, []Permission{PermConfigWrite})

	// Verify old permission removed.
	if m.HasPermission(RoleRider, PermUsersRead) {
		t.Error("rider should not have users:read after SetPermissions")
	}

	// Verify new permission added.
	if !m.HasPermission(RoleRider, PermConfigWrite) {
		t.Error("rider should have config:write after SetPermissions")
	}
}

func TestManager_AddPermission(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)

	// Verify rider doesn't have config:write.
	if m.HasPermission(RoleRider, PermConfigWrite) {
		t.Fatal("rider should not have config:write by default")
	}

	// Add permission.
	m.AddPermission(RoleRider, PermConfigWrite)

	// Verify permission added.
	if !m.HasPermission(RoleRider, PermConfigWrite) {
		t.Error("rider should have config:write after AddPermission")
	}

	// Old permissions should still exist.
	if !m.HasPermission(RoleRider, PermUsersRead) {
		t.Error("rider should still have users:read")
	}
}

func TestManager_AddPermission_NewRole(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)

	// Add permission to a new role.
	m.AddPermission(Role("custom"), PermUsersRead)

	if !m.HasPermission(Role("custom"), PermUsersRead) {
		t.Error("custom role should have users:read after AddPermission")
	}
}

func TestManager_RemovePermission(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)

	// Verify rider has users:read.
	if !m.HasPermission(RoleRider, PermUsersRead) {
		t.Fatal("rider should have users:read by default")
	}

	// Remove permission.
	m.RemovePermission(RoleRider, PermUsersRead)

	// Verify permission removed.
	if m.HasPermission(RoleRider, PermUsersRead) {
		t.Error("rider should not have users:read after RemovePermission")
	}
}

func TestManager_RemovePermission_NonExistent(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)

	// Should not panic.
	m.RemovePermission(Role("nonexistent"), PermUsersRead)
	m.RemovePermission(RoleRider, Permission("nonexistent"))
}

func TestChecker(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)
	c := NewChecker(m)

	ctx := txcontext.WithClaims(context.Background(), txcontext.UserClaims{
		UserID: "user-123",
		Roles:  []string{"rider"},
	})

	t.Run("Can", func(t *testing.T) {
		t.Parallel()
		if !c.Can(ctx, PermUsersRead) {
			t.Error("Can(users:read) should return true")
		}
		if c.Can(ctx, PermConfigWrite) {
			t.Error("Can(config:write) should return false")
		}
	})

	t.Run("CanAny", func(t *testing.T) {
		t.Parallel()
		if !c.CanAny(ctx, PermConfigWrite, PermUsersRead) {
			t.Error("CanAny should return true")
		}
		if c.CanAny(ctx, PermConfigWrite, PermConfigRead) {
			t.Error("CanAny should return false")
		}
	})

	t.Run("CanAll", func(t *testing.T) {
		t.Parallel()
		if !c.CanAll(ctx, PermUsersRead, PermRidesRead) {
			t.Error("CanAll should return true")
		}
		if c.CanAll(ctx, PermUsersRead, PermConfigRead) {
			t.Error("CanAll should return false")
		}
	})

	t.Run("IsRole", func(t *testing.T) {
		t.Parallel()
		if !c.IsRole(ctx, RoleRider) {
			t.Error("IsRole(rider) should return true")
		}
		if c.IsRole(ctx, RoleAdmin) {
			t.Error("IsRole(admin) should return false")
		}
	})

	t.Run("IsAnyRole", func(t *testing.T) {
		t.Parallel()
		if !c.IsAnyRole(ctx, RoleAdmin, RoleRider) {
			t.Error("IsAnyRole should return true")
		}
		if c.IsAnyRole(ctx, RoleAdmin, RoleSuperAdmin) {
			t.Error("IsAnyRole should return false")
		}
	})
}

func TestSuperAdminHasAllPermissions(t *testing.T) {
	t.Parallel()

	m := NewManager(nil)

	for _, perm := range AllPermissions() {
		if !m.HasPermission(RoleSuperAdmin, perm) {
			t.Errorf("super_admin should have %v permission", perm)
		}
	}
}
