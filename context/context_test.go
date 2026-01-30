package context

import (
	"context"
	"testing"
	"time"
)

func TestRequestID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ctx      context.Context
		setup    func(context.Context) context.Context
		expected string
	}{
		{
			name:     "nil context",
			ctx:      nil,
			setup:    func(ctx context.Context) context.Context { return ctx },
			expected: "",
		},
		{
			name:     "empty context",
			ctx:      context.Background(),
			setup:    func(ctx context.Context) context.Context { return ctx },
			expected: "",
		},
		{
			name:     "with request ID",
			ctx:      context.Background(),
			setup:    func(ctx context.Context) context.Context { return WithRequestID(ctx, "req-123") },
			expected: "req-123",
		},
		{
			name:     "with empty request ID",
			ctx:      context.Background(),
			setup:    func(ctx context.Context) context.Context { return WithRequestID(ctx, "") },
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := tt.setup(tt.ctx)
			if got := RequestID(ctx); got != tt.expected {
				t.Errorf("RequestID() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCorrelationID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ctx      context.Context
		setup    func(context.Context) context.Context
		expected string
	}{
		{
			name:     "nil context",
			ctx:      nil,
			setup:    func(ctx context.Context) context.Context { return ctx },
			expected: "",
		},
		{
			name:     "empty context",
			ctx:      context.Background(),
			setup:    func(ctx context.Context) context.Context { return ctx },
			expected: "",
		},
		{
			name:     "with correlation ID",
			ctx:      context.Background(),
			setup:    func(ctx context.Context) context.Context { return WithCorrelationID(ctx, "corr-456") },
			expected: "corr-456",
		},
		{
			name:     "with empty correlation ID",
			ctx:      context.Background(),
			setup:    func(ctx context.Context) context.Context { return WithCorrelationID(ctx, "") },
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := tt.setup(tt.ctx)
			if got := CorrelationID(ctx); got != tt.expected {
				t.Errorf("CorrelationID() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestUserClaims_IsZero(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		claims   UserClaims
		expected bool
	}{
		{
			name:     "zero claims",
			claims:   UserClaims{},
			expected: true,
		},
		{
			name:     "with user ID",
			claims:   UserClaims{UserID: "user-123"},
			expected: false,
		},
		{
			name:     "with only roles",
			claims:   UserClaims{Roles: []string{"admin"}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.claims.IsZero(); got != tt.expected {
				t.Errorf("IsZero() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestUserClaims_HasRole(t *testing.T) {
	t.Parallel()

	claims := UserClaims{
		UserID: "user-123",
		Roles:  []string{"rider", "premium"},
	}

	tests := []struct {
		name     string
		role     string
		expected bool
	}{
		{"has rider role", "rider", true},
		{"has premium role", "premium", true},
		{"does not have admin role", "admin", false},
		{"empty role", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := claims.HasRole(tt.role); got != tt.expected {
				t.Errorf("HasRole(%q) = %v, want %v", tt.role, got, tt.expected)
			}
		})
	}
}

func TestUserClaims_HasAnyRole(t *testing.T) {
	t.Parallel()

	claims := UserClaims{
		UserID: "user-123",
		Roles:  []string{"rider", "premium"},
	}

	tests := []struct {
		name     string
		roles    []string
		expected bool
	}{
		{"has one of the roles", []string{"admin", "rider"}, true},
		{"has none of the roles", []string{"admin", "super_admin"}, false},
		{"empty roles list", []string{}, false},
		{"has all roles", []string{"rider", "premium"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := claims.HasAnyRole(tt.roles...); got != tt.expected {
				t.Errorf("HasAnyRole(%v) = %v, want %v", tt.roles, got, tt.expected)
			}
		})
	}
}

func TestUserClaims_HasAllRoles(t *testing.T) {
	t.Parallel()

	claims := UserClaims{
		UserID: "user-123",
		Roles:  []string{"rider", "premium", "verified"},
	}

	tests := []struct {
		name     string
		roles    []string
		expected bool
	}{
		{"has all roles", []string{"rider", "premium"}, true},
		{"missing one role", []string{"rider", "admin"}, false},
		{"empty roles list", []string{}, true},
		{"single role present", []string{"rider"}, true},
		{"single role absent", []string{"admin"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := claims.HasAllRoles(tt.roles...); got != tt.expected {
				t.Errorf("HasAllRoles(%v) = %v, want %v", tt.roles, got, tt.expected)
			}
		})
	}
}

func TestClaims(t *testing.T) {
	t.Parallel()

	now := time.Now()
	testClaims := UserClaims{
		UserID:    "user-123",
		UserType:  "rider",
		Roles:     []string{"rider"},
		TokenID:   "token-456",
		IssuedAt:  now,
		ExpiresAt: now.Add(24 * time.Hour),
	}

	tests := []struct {
		name     string
		ctx      context.Context
		setup    func(context.Context) context.Context
		expected UserClaims
	}{
		{
			name:     "nil context",
			ctx:      nil,
			setup:    func(ctx context.Context) context.Context { return ctx },
			expected: UserClaims{},
		},
		{
			name:     "empty context",
			ctx:      context.Background(),
			setup:    func(ctx context.Context) context.Context { return ctx },
			expected: UserClaims{},
		},
		{
			name:     "with claims",
			ctx:      context.Background(),
			setup:    func(ctx context.Context) context.Context { return WithClaims(ctx, testClaims) },
			expected: testClaims,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := tt.setup(tt.ctx)
			got := Claims(ctx)
			if got.UserID != tt.expected.UserID {
				t.Errorf("Claims().UserID = %v, want %v", got.UserID, tt.expected.UserID)
			}
			if got.UserType != tt.expected.UserType {
				t.Errorf("Claims().UserType = %v, want %v", got.UserType, tt.expected.UserType)
			}
		})
	}
}

func TestUserID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	claims := UserClaims{UserID: "user-789"}
	ctxWithClaims := WithClaims(ctx, claims)

	if got := UserID(ctx); got != "" {
		t.Errorf("UserID(empty ctx) = %v, want empty", got)
	}
	if got := UserID(ctxWithClaims); got != "user-789" {
		t.Errorf("UserID(ctx with claims) = %v, want user-789", got)
	}
}

func TestUserType(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	claims := UserClaims{UserID: "user-789", UserType: "driver"}
	ctxWithClaims := WithClaims(ctx, claims)

	if got := UserType(ctx); got != "" {
		t.Errorf("UserType(empty ctx) = %v, want empty", got)
	}
	if got := UserType(ctxWithClaims); got != "driver" {
		t.Errorf("UserType(ctx with claims) = %v, want driver", got)
	}
}

func TestIsAuthenticated(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ctx      context.Context
		expected bool
	}{
		{
			name:     "nil context",
			ctx:      nil,
			expected: false,
		},
		{
			name:     "empty context",
			ctx:      context.Background(),
			expected: false,
		},
		{
			name:     "with empty claims",
			ctx:      WithClaims(context.Background(), UserClaims{}),
			expected: false,
		},
		{
			name:     "with valid claims",
			ctx:      WithClaims(context.Background(), UserClaims{UserID: "user-123"}),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsAuthenticated(tt.ctx); got != tt.expected {
				t.Errorf("IsAuthenticated() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestWithTimeout(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	timeout := 100 * time.Millisecond

	ctxWithTimeout, cancel := WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case <-ctxWithTimeout.Done():
		t.Error("context should not be done immediately")
	default:
		// Expected
	}

	// Wait for timeout.
	time.Sleep(150 * time.Millisecond)

	select {
	case <-ctxWithTimeout.Done():
		if ctxWithTimeout.Err() != context.DeadlineExceeded {
			t.Errorf("expected DeadlineExceeded, got %v", ctxWithTimeout.Err())
		}
	default:
		t.Error("context should be done after timeout")
	}
}

func TestWithDeadline(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	deadline := time.Now().Add(100 * time.Millisecond)

	ctxWithDeadline, cancel := WithDeadline(ctx, deadline)
	defer cancel()

	select {
	case <-ctxWithDeadline.Done():
		t.Error("context should not be done immediately")
	default:
		// Expected
	}

	// Wait past deadline.
	time.Sleep(150 * time.Millisecond)

	select {
	case <-ctxWithDeadline.Done():
		if ctxWithDeadline.Err() != context.DeadlineExceeded {
			t.Errorf("expected DeadlineExceeded, got %v", ctxWithDeadline.Err())
		}
	default:
		t.Error("context should be done after deadline")
	}
}

func TestHeaderConstants(t *testing.T) {
	t.Parallel()

	if HeaderRequestID != "X-Request-ID" {
		t.Errorf("HeaderRequestID = %v, want X-Request-ID", HeaderRequestID)
	}
	if HeaderCorrelationID != "X-Correlation-ID" {
		t.Errorf("HeaderCorrelationID = %v, want X-Correlation-ID", HeaderCorrelationID)
	}
}

func TestContextChaining(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ctx = WithRequestID(ctx, "req-123")
	ctx = WithCorrelationID(ctx, "corr-456")
	ctx = WithClaims(ctx, UserClaims{UserID: "user-789", UserType: "rider"})

	if got := RequestID(ctx); got != "req-123" {
		t.Errorf("RequestID() = %v, want req-123", got)
	}
	if got := CorrelationID(ctx); got != "corr-456" {
		t.Errorf("CorrelationID() = %v, want corr-456", got)
	}
	if got := UserID(ctx); got != "user-789" {
		t.Errorf("UserID() = %v, want user-789", got)
	}
	if got := UserType(ctx); got != "rider" {
		t.Errorf("UserType() = %v, want rider", got)
	}
}

func TestUserClaimsWithNoRoles(t *testing.T) {
	t.Parallel()

	claims := UserClaims{
		UserID: "user-123",
		Roles:  nil,
	}

	if claims.HasRole("admin") {
		t.Error("HasRole should return false for nil roles")
	}
	if claims.HasAnyRole("admin", "rider") {
		t.Error("HasAnyRole should return false for nil roles")
	}
	if !claims.HasAllRoles() {
		t.Error("HasAllRoles with empty args should return true")
	}
}
