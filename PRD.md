# txova-go-core

## Overview
Core application infrastructure providing HTTP server setup, configuration management, authentication, structured logging, and error handling patterns.

**Module:** `github.com/txova/txova-go-core`

---

## Packages

### `app` - Application Bootstrap
| Feature | Priority | Description |
|---------|----------|-------------|
| Graceful startup | P0 | Initialize dependencies in order, fail fast on errors |
| Graceful shutdown | P0 | Handle SIGTERM/SIGINT, drain connections, close resources |
| Health endpoints | P0 | `/health/live` and `/health/ready` endpoints |
| Panic recovery | P0 | Recover from panics, log stack trace, return 500 |
| Request timeout | P0 | Global timeout with context cancellation |

**Requirements:**
- Shutdown must wait for in-flight requests (max 30 seconds)
- Health check must verify all critical dependencies
- Panic recovery must not leak internal details to clients
- Support dependency injection for testability

---

### `config` - Configuration Management
| Feature | Priority | Description |
|---------|----------|-------------|
| YAML loading | P0 | Load from config file with environment override |
| Env variables | P0 | Override config via environment (12-factor) |
| Validation | P0 | Validate required fields on load |
| Secrets handling | P0 | Support for secret references (vault, env) |
| Hot reload | P2 | Reload config without restart |

**Configuration Structure:**
| Section | Fields |
|---------|--------|
| server | host, port, read_timeout, write_timeout, shutdown_timeout |
| database | host, port, name, user, password, max_connections, ssl_mode |
| redis | host, port, password, db, pool_size |
| kafka | brokers[], group_id, client_id |
| auth | jwt_secret, jwt_issuer, token_expiry, refresh_expiry |
| logging | level, format (json/text), output |
| observability | metrics_port, tracing_endpoint, service_name |

**Requirements:**
- Environment variables override YAML (e.g., `TXOVA_DATABASE_HOST`)
- Sensitive fields must not be logged
- Provide defaults for non-critical settings
- Fail startup if required config is missing

---

### `server` - HTTP Server
| Feature | Priority | Description |
|---------|----------|-------------|
| Chi router | P0 | Use go-chi/chi for routing |
| Middleware chain | P0 | Standard middleware in correct order |
| CORS | P0 | Configurable CORS for mobile clients |
| Request ID | P0 | Inject unique ID for request tracing |
| JSON responses | P0 | Consistent response envelope |

**Standard Middleware Order:**
1. Request ID injection
2. Panic recovery
3. Structured logging
4. Timeout
5. CORS
6. Metrics collection
7. Authentication (where required)
8. Rate limiting

**Response Envelope:**
| Field | Description |
|-------|-------------|
| data | Response payload (success) |
| error | Error object (failure) |
| error.code | Machine-readable error code |
| error.message | Human-readable message |
| meta | Pagination, timestamps, request_id |

---

### `auth` - Authentication
| Feature | Priority | Description |
|---------|----------|-------------|
| JWT generation | P0 | Create signed access tokens |
| JWT validation | P0 | Verify signature and expiry |
| Claims extraction | P0 | Extract user info from token |
| Refresh tokens | P0 | Long-lived refresh token flow |
| Token revocation | P1 | Blacklist revoked tokens |

**JWT Claims:**
| Claim | Type | Description |
|-------|------|-------------|
| sub | UserID | Subject (user ID) |
| type | UserType | rider, driver, admin |
| roles | []string | Permission roles |
| exp | timestamp | Expiration time |
| iat | timestamp | Issued at |
| jti | string | Unique token ID |

**Requirements:**
- Use RS256 algorithm for JWT signing
- Access token expiry: 24 hours (configurable)
- Refresh token expiry: 30 days (configurable)
- Store refresh tokens in Redis with user association
- Revoke all tokens on password change

---

### `rbac` - Role-Based Access Control
| Role | Description |
|------|-------------|
| rider | Standard rider permissions |
| driver | Standard driver permissions |
| support | Customer support access |
| ops | Operations team access |
| admin | Full administrative access |
| super_admin | System-level access |

**Permission Model:**
| Permission | Description |
|------------|-------------|
| users:read | View user profiles |
| users:write | Modify user data |
| drivers:read | View driver info |
| drivers:write | Modify driver data |
| drivers:verify | Approve/reject drivers |
| rides:read | View ride history |
| rides:cancel | Cancel active rides |
| payments:read | View payment data |
| payments:refund | Issue refunds |
| config:read | View system config |
| config:write | Modify system config |

**Requirements:**
- Permissions are additive (role grants permissions)
- Support permission checking at route and handler level
- Cache role-permission mappings in memory
- Log all permission denials

---

### `logging` - Structured Logging
| Feature | Priority | Description |
|---------|----------|-------------|
| slog integration | P0 | Use Go 1.21+ slog package |
| JSON output | P0 | Structured JSON for production |
| Context fields | P0 | Extract request_id, user_id from context |
| PII masking | P0 | Mask sensitive data (phone, email) |
| Level filtering | P0 | Configurable log levels |

**Standard Fields:**
| Field | Description |
|-------|-------------|
| timestamp | ISO8601 format |
| level | debug, info, warn, error |
| message | Log message |
| service | Service name |
| request_id | Correlation ID |
| user_id | Authenticated user (if present) |
| duration_ms | Request duration |
| error | Error details (if applicable) |

**Requirements:**
- Default to JSON in production, text in development
- Automatically inject context fields (request_id, user_id)
- Mask phone numbers: +258841234567 -> +258****4567
- Mask emails: test@example.com -> t***@example.com
- Never log passwords, tokens, or API keys

---

### `errors` - Error Handling
| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| VALIDATION_ERROR | 400 | Invalid input data |
| INVALID_CREDENTIALS | 401 | Wrong username/password |
| TOKEN_EXPIRED | 401 | JWT has expired |
| TOKEN_INVALID | 401 | JWT signature invalid |
| FORBIDDEN | 403 | Insufficient permissions |
| NOT_FOUND | 404 | Resource doesn't exist |
| CONFLICT | 409 | Resource already exists |
| RATE_LIMITED | 429 | Too many requests |
| INTERNAL_ERROR | 500 | Unexpected server error |
| SERVICE_UNAVAILABLE | 503 | Dependency unavailable |

**Requirements:**
- All errors must have code + message
- Internal errors must not expose stack traces to clients
- Log full error details server-side
- Support error wrapping for context
- Provide `Is()` and `As()` methods for error checking

---

### `context` - Context Utilities
| Feature | Description |
|---------|-------------|
| Request ID | Get/set request ID in context |
| User claims | Get/set authenticated user claims |
| Correlation ID | Propagate across service calls |
| Timeout | Context with configurable timeout |

**Requirements:**
- All context keys must be unexported types
- Provide typed getters that return zero values if not set
- Correlation ID must propagate via HTTP headers

---

## Dependencies

**Internal:**
- `txova-go-types`

**External:**
- `github.com/go-chi/chi/v5` — HTTP router
- `github.com/golang-jwt/jwt/v5` — JWT handling
- `gopkg.in/yaml.v3` — YAML parsing

---

## Success Metrics
| Metric | Target |
|--------|--------|
| Test coverage | > 85% |
| Startup time | < 5 seconds |
| Graceful shutdown success | 100% |
| Auth validation latency | < 5ms |
