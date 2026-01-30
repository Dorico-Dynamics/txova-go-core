# txova-go-core Usage Guide

This guide provides examples for using the txova-go-core library packages.

## Installation

```bash
go get github.com/Dorico-Dynamics/txova-go-core
```

## Packages

### errors - Standardized Error Handling

The errors package provides application-level errors with machine-readable codes and HTTP status mappings.

```go
import "github.com/Dorico-Dynamics/txova-go-core/errors"

// Create typed errors
err := errors.ValidationError("email is required")
err = errors.NotFound("user not found")
err = errors.Forbidden("access denied")
err = errors.InternalError("database connection failed")

// Wrap errors with context
err = errors.Wrap(errors.CodeInternalError, "failed to create user", dbErr)

// Check error types
if errors.IsNotFound(err) {
    // Handle not found
}
if errors.IsForbidden(err) {
    // Handle forbidden
}

// Get HTTP status for error
status := err.HTTPStatus() // Returns appropriate HTTP status code
```

### context - Request Context Utilities

The context package provides utilities for managing request-scoped values.

```go
import txcontext "github.com/Dorico-Dynamics/txova-go-core/context"

// Set and get request ID
ctx = txcontext.WithRequestID(ctx, "req-123")
requestID := txcontext.RequestID(ctx)

// Set and get correlation ID
ctx = txcontext.WithCorrelationID(ctx, "corr-456")
correlationID := txcontext.CorrelationID(ctx)

// Set and get user claims
claims := &txcontext.UserClaims{
    UserID:   userID,
    UserType: enums.UserTypeRider,
    Roles:    []string{"rider"},
}
ctx = txcontext.WithClaims(ctx, claims)

// Check authentication
if txcontext.IsAuthenticated(ctx) {
    userID := txcontext.UserID(ctx)
}

// Check roles
if txcontext.Claims(ctx).HasRole("admin") {
    // Admin access
}
```

### logging - Structured Logging with PII Masking

The logging package provides structured logging with automatic PII masking.

```go
import "github.com/Dorico-Dynamics/txova-go-core/logging"

// Create a logger
logger := logging.New(logging.ProductionConfig("my-service"))

// Basic logging
logger.Info("user logged in", "user_id", userID)
logger.Error("request failed", "error", err.Error())

// Context-aware logging (extracts request_id, user_id automatically)
logger.InfoContext(ctx, "processing request")

// PII masking
phone := logging.MaskPhone("+258841234567")  // Returns "+258****4567"
email := logging.MaskEmail("user@example.com") // Returns "u***@example.com"

// Safe attribute helpers
attr := logging.PhoneAttr("phone", "+258841234567") // Automatically masked
attr := logging.EmailAttr("email", "user@example.com") // Automatically masked
attr := logging.SafeAttr("password", secret) // Returns [REDACTED] for sensitive fields
```

### config - Configuration Management

The config package provides YAML file loading with environment variable overrides.

```go
import "github.com/Dorico-Dynamics/txova-go-core/config"

// Load from file with env overrides
cfg, err := config.Load("config.yaml")

// Load purely from environment variables
cfg, err := config.LoadFromEnv()

// Access configuration
fmt.Println(cfg.Server.Address()) // "0.0.0.0:8080"
fmt.Println(cfg.Database.DSN())   // PostgreSQL connection string

// Environment variable format: TXOVA_SECTION_FIELD
// Example: TXOVA_DATABASE_HOST=localhost
```

Example config.yaml:
```yaml
server:
  host: "0.0.0.0"
  port: 8080
  read_timeout: 30s
  write_timeout: 30s

database:
  host: "localhost"
  port: 5432
  name: "txova"
  user: "postgres"
  password: "${env:DATABASE_PASSWORD}"

auth:
  jwt_secret: "${env:JWT_SECRET}"
  token_expiry: 24h

logging:
  level: "info"
  format: "json"
```

### auth - JWT Authentication

The auth package provides JWT token generation and validation with RS256 signing.

```go
import "github.com/Dorico-Dynamics/txova-go-core/auth"

// Create auth service with RSA keys
authSvc, err := auth.NewService(auth.Config{
    PrivateKey:        privateKey,
    PublicKey:         publicKey,
    Issuer:            "txova",
    AccessTokenExpiry:  24 * time.Hour,
    RefreshTokenExpiry: 30 * 24 * time.Hour,
})

// Generate token pair
tokenPair, err := authSvc.GenerateTokenPair(userID, enums.UserTypeRider, []string{"rider"})
// Returns: AccessToken, RefreshToken, ExpiresIn, ExpiresAt

// Validate access token
claims, err := authSvc.ValidateAccessToken(tokenString)
if err != nil {
    if errors.IsTokenExpired(err) {
        // Token expired, use refresh token
    }
}

// Refresh tokens
newTokenPair, err := authSvc.RefreshTokens(refreshToken)

// Token revocation (with blacklist)
blacklist := NewRedisBlacklist(redisClient) // implement TokenBlacklist interface
svcWithBlacklist, _ := auth.NewServiceWithBlacklist(cfg, blacklist)
err := svcWithBlacklist.RevokeToken(ctx, tokenString)
```

### rbac - Role-Based Access Control

The rbac package provides role-based access control with predefined roles and permissions.

```go
import "github.com/Dorico-Dynamics/txova-go-core/rbac"

// Create RBAC manager with default permissions
manager := rbac.NewManager(nil)

// Check permissions
if manager.HasPermission(rbac.RoleRider, rbac.PermUsersRead) {
    // Rider can read users
}

// Check from context (in handlers)
err := manager.CheckPermission(ctx, rbac.PermUsersWrite)
if err != nil {
    // Permission denied
}

// Check any/all permissions
err := manager.CheckAnyPermission(ctx, rbac.PermUsersRead, rbac.PermUsersWrite)
err := manager.CheckAllPermissions(ctx, rbac.PermUsersRead, rbac.PermRidesRead)

// Require specific role
err := manager.RequireRole(ctx, rbac.RoleAdmin)

// Available roles: rider, driver, support, ops, admin, super_admin
// Available permissions: users:read, users:write, drivers:read, drivers:write,
//   drivers:verify, rides:read, rides:cancel, payments:read, payments:refund,
//   config:read, config:write
```

### server - HTTP Server with Middleware

The server package provides HTTP server setup with Chi router and standard middleware.

```go
import "github.com/Dorico-Dynamics/txova-go-core/server"

// Create server
srv := server.New(server.DefaultConfig(), logger)

// Register routes
router := srv.Router()
router.Get("/api/users", listUsersHandler)
router.Post("/api/users", createUserHandler)

// Standard JSON responses
func createUserHandler(w http.ResponseWriter, r *http.Request) {
    // Decode request
    var req CreateUserRequest
    if err := server.DecodeJSON(r, &req); err != nil {
        server.HandleError(w, r, err)
        return
    }

    // Process and respond
    user := createUser(req)
    server.Created(w, r, user) // 201 with JSON envelope
}

// Response helpers
server.OK(w, r, data)           // 200 OK
server.Created(w, r, data)      // 201 Created
server.NoContent(w)             // 204 No Content
server.BadRequest(w, r, "msg")  // 400 Bad Request
server.NotFound(w, r, "msg")    // 404 Not Found
server.InternalError(w, r)      // 500 Internal Server Error

// Metrics collection
srv.WithMetrics(metricsCollector) // implement MetricsCollector interface
```

### app - Application Lifecycle Management

The app package provides graceful startup/shutdown and health endpoints.

```go
import "github.com/Dorico-Dynamics/txova-go-core/app"

// Create application
application := app.New(app.Config{
    Name:            "my-service",
    Version:         "1.0.0",
    ShutdownTimeout: 30 * time.Second,
},
    app.WithLogger(logger),
    app.WithServer(srv),
)

// Add health checks
application.AddHealthCheck(app.NewHealthCheck("database", func(ctx context.Context) error {
    return db.PingContext(ctx)
}))
application.AddHealthCheck(app.NewHealthCheck("redis", func(ctx context.Context) error {
    return redis.Ping(ctx).Err()
}))

// Add initializers (run on startup)
application.AddInitializer(app.NewInitializer("database", func(ctx context.Context) error {
    return db.Connect()
}))

// Add closers (run on shutdown)
application.AddCloser(app.NewCloser("database", func(ctx context.Context) error {
    return db.Close()
}))

// Register health routes
app.RegisterHealthRoutes(srv, application)
// GET /health/live  - Liveness probe
// GET /health/ready - Readiness probe
// GET /health       - Full health check

// Run application (blocks until shutdown)
if err := application.Run(); err != nil {
    log.Fatal(err)
}
```

## Response Format

All JSON responses follow the standard envelope format:

```json
{
  "data": { ... },
  "meta": {
    "request_id": "req-123",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

Error responses:
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "email is required"
  },
  "meta": {
    "request_id": "req-123",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

## Dependencies

- **txova-go-types**: Typed identifiers and domain types
- **go-chi/chi/v5**: HTTP router
- **golang-jwt/jwt/v5**: JWT handling
- **gopkg.in/yaml.v3**: YAML parsing
