# txova-go-core Execution Plan

**Version:** 1.0  
**Module:** `github.com/Dorico-Dynamics/txova-go-core`  
**Target Test Coverage:** >85%  
**Internal Dependencies:** txova-go-types  
**External Dependencies:** go-chi/chi/v5, golang-jwt/jwt/v5, gopkg.in/yaml.v3

---

## Phase 1: Project Setup & Foundation (Week 1)

### 1.1 Project Initialization
- [ ] Initialize Go module with `go mod init github.com/Dorico-Dynamics/txova-go-core`
- [ ] Add dependency on `txova-go-types`
- [ ] Add external dependencies (chi, jwt, yaml)
- [ ] Create directory structure for all packages
- [ ] Set up `.gitignore` for Go projects
- [ ] Configure golangci-lint with strict rules
- [ ] Set up GitHub Actions workflows (test, release)

### 1.2 Package: `errors` - Error Handling
- [ ] Define `AppError` type with code, message, HTTP status, and wrapped error
- [ ] Implement standard error codes (VALIDATION_ERROR, NOT_FOUND, FORBIDDEN, etc.)
- [ ] Implement constructor functions for each error type
- [ ] Implement `Error()`, `Is()`, `As()`, and `Unwrap()` methods
- [ ] Implement `WriteError()` to write JSON error responses
- [ ] Ensure internal errors never expose stack traces to clients
- [ ] Write tests for all error types and response formatting

**Deliverables:**
- [ ] `errors/` package with standardized error handling
- [ ] Full test coverage for error creation, wrapping, and HTTP responses

---

## Phase 2: Context & Logging (Week 2)

### 2.1 Package: `context` - Context Utilities
- [ ] Define unexported context key types
- [ ] Implement request ID get/set functions
- [ ] Implement user claims get/set functions
- [ ] Implement correlation ID get/set with HTTP header propagation
- [ ] Implement timeout context helper
- [ ] Ensure typed getters return zero values when not set
- [ ] Write tests for all context operations

**Deliverables:**
- [ ] `context/` package with context utilities
- [ ] Tests covering all get/set operations and edge cases

### 2.2 Package: `logging` - Structured Logging
- [ ] Implement logger using Go slog package
- [ ] Implement JSON output formatter for production
- [ ] Implement text output formatter for development
- [ ] Implement context field extraction (request_id, user_id)
- [ ] Implement PII masking for phone numbers (+258****4567 format)
- [ ] Implement PII masking for emails (t***@example.com format)
- [ ] Implement log level filtering (debug, info, warn, error)
- [ ] Add standard fields (timestamp, level, message, service, duration_ms)
- [ ] Ensure passwords, tokens, and API keys are never logged
- [ ] Write tests for formatting, masking, and level filtering

**Deliverables:**
- [ ] `logging/` package with structured logging
- [ ] Tests for JSON/text output, PII masking, and context extraction

---

## Phase 3: Configuration (Week 3)

### 3.1 Package: `config` - Configuration Management
- [ ] Define config structs for all sections (server, database, redis, kafka, auth, logging, observability)
- [ ] Implement YAML file loading
- [ ] Implement environment variable overrides (TXOVA_DATABASE_HOST format)
- [ ] Implement required field validation with startup failure
- [ ] Implement default values for non-critical settings
- [ ] Implement secrets handling (support vault/env references)
- [ ] Ensure sensitive fields are never logged
- [ ] Write tests for loading, overrides, validation, and defaults

**Deliverables:**
- [ ] `config/` package with configuration management
- [ ] Tests for YAML loading, env overrides, validation, and secrets

---

## Phase 4: Authentication & Authorization (Week 4)

### 4.1 Package: `auth` - JWT Authentication
- [ ] Implement JWT token generation with RS256 algorithm
- [ ] Implement JWT validation (signature, expiry)
- [ ] Implement claims extraction (sub, type, roles, exp, iat, jti)
- [ ] Implement refresh token flow with configurable expiry
- [ ] Implement token revocation support (blacklist interface)
- [ ] Configure default expiries (access: 24h, refresh: 30d)
- [ ] Write tests for generation, validation, claims, and refresh flow

**Deliverables:**
- [ ] `auth/` package with JWT authentication
- [ ] Tests for token lifecycle, validation errors, and refresh flow

### 4.2 Package: `rbac` - Role-Based Access Control
- [ ] Define roles (rider, driver, support, ops, admin, super_admin)
- [ ] Define permissions (users:read, users:write, drivers:verify, etc.)
- [ ] Implement role-permission mapping with in-memory cache
- [ ] Implement permission checking functions
- [ ] Implement middleware for route-level permission checks
- [ ] Implement handler-level permission helpers
- [ ] Log all permission denials
- [ ] Write tests for role mappings and permission checks

**Deliverables:**
- [ ] `rbac/` package with role-based access control
- [ ] Tests for all roles, permissions, and denial logging

---

## Phase 5: HTTP Server (Week 5)

### 5.1 Package: `server` - HTTP Server Setup
- [ ] Implement server struct with Chi router
- [ ] Implement configurable CORS middleware
- [ ] Implement request ID injection middleware
- [ ] Implement panic recovery middleware (no internal details leaked)
- [ ] Implement structured logging middleware
- [ ] Implement timeout middleware with context cancellation
- [ ] Implement metrics collection middleware (interface for observability)
- [ ] Implement standard middleware chain in correct order
- [ ] Implement consistent JSON response envelope (data, error, meta)
- [ ] Write tests for middleware chain and response formatting

**Deliverables:**
- [ ] `server/` package with HTTP server setup
- [ ] Tests for all middleware and response envelope

---

## Phase 6: Application Bootstrap (Week 6)

### 6.1 Package: `app` - Application Lifecycle
- [ ] Implement graceful startup with ordered dependency initialization
- [ ] Implement fail-fast on initialization errors
- [ ] Implement graceful shutdown (SIGTERM/SIGINT handling)
- [ ] Implement connection draining (max 30 seconds wait)
- [ ] Implement resource cleanup on shutdown
- [ ] Implement `/health/live` endpoint (liveness probe)
- [ ] Implement `/health/ready` endpoint with dependency checks
- [ ] Implement panic recovery at application level
- [ ] Support dependency injection for testability
- [ ] Write tests for startup, shutdown, and health checks

**Deliverables:**
- [ ] `app/` package with application bootstrap
- [ ] Tests for lifecycle management and health endpoints

---

## Phase 7: Integration & Quality Assurance (Week 7)

### 7.1 Cross-Package Integration
- [ ] Verify all packages work together without circular dependencies
- [ ] Ensure consistent error handling across all packages
- [ ] Validate context propagation through middleware chain
- [ ] Test full request flow (auth → rbac → handler → response)

### 7.2 Quality Assurance
- [ ] Run full test suite and verify >85% coverage
- [ ] Run golangci-lint and fix all issues
- [ ] Run `go vet` and address all warnings
- [ ] Test with `go build` for all target platforms
- [ ] Verify startup time < 5 seconds
- [ ] Verify auth validation latency < 5ms
- [ ] Verify graceful shutdown completes successfully

### 7.3 Documentation
- [ ] Ensure all exported types and functions have godoc comments
- [ ] Create USAGE.md with package documentation and examples

### 7.4 Release
- [ ] Tag release as v1.0.0
- [ ] Push to GitHub
- [ ] Verify module is accessible via `go get`

**Deliverables:**
- [ ] Complete, tested library
- [ ] >85% test coverage verified
- [ ] v1.0.0 release tagged and published

---

## Success Criteria

| Criteria | Target |
|----------|--------|
| Test Coverage | >85% |
| Startup Time | <5 seconds |
| Graceful Shutdown | 100% success |
| Auth Validation Latency | <5ms |
| Linting Errors | 0 |
| go vet Warnings | 0 |

---

## Package Dependency Order

```
errors (no internal deps)
    ↓
context (no internal deps)
    ↓
logging (depends on context)
    ↓
config (no internal deps)
    ↓
auth (depends on errors, config)
    ↓
rbac (depends on errors, auth, logging)
    ↓
server (depends on errors, context, logging, auth, rbac)
    ↓
app (depends on all packages)
```

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| JWT key management complexity | Support both file and env-based key loading |
| Config validation edge cases | Comprehensive test matrix for all config combinations |
| Middleware ordering bugs | Explicit ordering with integration tests |
| Graceful shutdown timeout issues | Configurable timeout with hard deadline |
| PII leakage in logs | Automated tests verifying masking patterns |
| Permission check bypasses | Route-level and handler-level enforcement |
