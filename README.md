# txova-go-core

Core library providing HTTP server setup, configuration management, authentication, logging, and error handling for all Txova Go services.

## Overview

`txova-go-core` provides the foundational building blocks that every Txova service needs, including HTTP server configuration, JWT authentication, RBAC, structured logging, and standardized error handling.

**Module:** `github.com/txova/txova-go-core`

## Features

- **HTTP Server** - Chi router setup with graceful shutdown
- **Configuration** - Environment-aware config loading from YAML and env vars
- **Authentication** - JWT token validation and claims extraction
- **Authorization** - Role-based access control (RBAC)
- **Logging** - Structured JSON logging with zerolog
- **Errors** - Standardized error types and HTTP error responses

## Packages

| Package | Description |
|---------|-------------|
| `server` | HTTP server setup with Chi router |
| `config` | Configuration loading and validation |
| `auth` | JWT validation and token handling |
| `rbac` | Role-based access control |
| `logger` | Structured logging with zerolog |
| `errors` | Error types and response formatting |

## Installation

```bash
go get github.com/txova/txova-go-core
```

## Usage

### HTTP Server

```go
import "github.com/txova/txova-go-core/server"

srv := server.New(server.Config{
    Port:            8080,
    ReadTimeout:     10 * time.Second,
    WriteTimeout:    30 * time.Second,
    ShutdownTimeout: 30 * time.Second,
})

srv.Route("/api/v1", func(r chi.Router) {
    r.Get("/health", healthHandler)
})

srv.Start(ctx)
```

### Configuration

```go
import "github.com/txova/txova-go-core/config"

type AppConfig struct {
    Server   config.ServerConfig   `yaml:"server"`
    Database config.DatabaseConfig `yaml:"database"`
    Redis    config.RedisConfig    `yaml:"redis"`
}

var cfg AppConfig
config.Load(&cfg, "config.yaml")
```

### JWT Authentication

```go
import "github.com/txova/txova-go-core/auth"

validator := auth.NewJWTValidator(auth.JWTConfig{
    PublicKeyPath: "/keys/jwt-public.pem",
    Issuer:        "txova-auth",
    Audience:      "txova-services",
})

claims, err := validator.ValidateToken(tokenString)
```

### Structured Logging

```go
import "github.com/txova/txova-go-core/logger"

log := logger.New(logger.Config{
    Level:   "info",
    Service: "ride-service",
})

log.Info().
    Str("ride_id", rideID.String()).
    Msg("Ride requested")
```

### Error Handling

```go
import "github.com/txova/txova-go-core/errors"

// Create domain error
err := errors.NotFound("USER_NOT_FOUND", "User not found")

// Write HTTP error response
errors.WriteError(w, err)
// Returns: {"error": {"code": "USER_NOT_FOUND", "message": "User not found"}}
```

## Dependencies

**Internal:**
- `txova-go-types`

**External:**
- `github.com/go-chi/chi/v5` - HTTP router
- `github.com/rs/zerolog` - Structured logging
- `github.com/golang-jwt/jwt/v5` - JWT handling
- `gopkg.in/yaml.v3` - YAML parsing

## Development

### Requirements

- Go 1.25+

### Testing

```bash
go test ./...
```

### Test Coverage Target

> 90%

## License

Proprietary - Dorico Dynamics
