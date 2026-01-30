// Package auth provides JWT-based authentication for the Txova platform.
// It supports RS256 signed access tokens, refresh tokens, and token validation.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	stderrors "errors"
	"fmt"
	"time"

	"github.com/Dorico-Dynamics/txova-go-types/enums"
	"github.com/Dorico-Dynamics/txova-go-types/ids"
	"github.com/golang-jwt/jwt/v5"

	"github.com/Dorico-Dynamics/txova-go-core/errors"
)

// TokenType distinguishes between access and refresh tokens.
type TokenType string

const (
	// TokenTypeAccess is for short-lived access tokens.
	TokenTypeAccess TokenType = "access"
	// TokenTypeRefresh is for long-lived refresh tokens.
	TokenTypeRefresh TokenType = "refresh"

	// defaultIssuer is the default token issuer.
	defaultIssuer = "txova"
)

// Claims represents the JWT claims for Txova tokens.
type Claims struct {
	jwt.RegisteredClaims
	UserID    ids.UserID     `json:"user_id"`
	UserType  enums.UserType `json:"user_type"`
	Roles     []string       `json:"roles,omitempty"`
	TokenType TokenType      `json:"token_type"`
}

// Config holds the authentication configuration.
type Config struct {
	// PrivateKey is the RSA private key for signing tokens.
	PrivateKey *rsa.PrivateKey
	// PublicKey is the RSA public key for verifying tokens.
	PublicKey *rsa.PublicKey
	// Issuer is the token issuer (iss claim).
	Issuer string
	// AccessTokenExpiry is the duration until access tokens expire.
	AccessTokenExpiry time.Duration
	// RefreshTokenExpiry is the duration until refresh tokens expire.
	RefreshTokenExpiry time.Duration
}

// DefaultConfig returns a default configuration.
// Note: In production, keys should be loaded from secure storage.
func DefaultConfig() Config {
	return Config{
		Issuer:             defaultIssuer,
		AccessTokenExpiry:  24 * time.Hour,
		RefreshTokenExpiry: 30 * 24 * time.Hour, // 30 days
	}
}

// Service provides authentication operations.
type Service struct {
	config Config
}

// NewService creates a new authentication service.
func NewService(cfg Config) (*Service, error) {
	if cfg.PrivateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}
	if cfg.PublicKey == nil {
		cfg.PublicKey = &cfg.PrivateKey.PublicKey
	}
	if cfg.Issuer == "" {
		cfg.Issuer = defaultIssuer
	}
	if cfg.AccessTokenExpiry == 0 {
		cfg.AccessTokenExpiry = 24 * time.Hour
	}
	if cfg.RefreshTokenExpiry == 0 {
		cfg.RefreshTokenExpiry = 30 * 24 * time.Hour
	}

	// Validate durations are positive.
	if cfg.AccessTokenExpiry < 0 {
		return nil, fmt.Errorf("access token expiry must be positive")
	}
	if cfg.RefreshTokenExpiry < 0 {
		return nil, fmt.Errorf("refresh token expiry must be positive")
	}

	return &Service{config: cfg}, nil
}

// TokenPair contains both access and refresh tokens.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// GenerateTokenPair generates both access and refresh tokens for a user.
func (s *Service) GenerateTokenPair(userID ids.UserID, userType enums.UserType, roles []string) (*TokenPair, error) {
	now := time.Now()

	// Generate access token.
	accessToken, err := s.generateToken(userID, userType, roles, TokenTypeAccess, now)
	if err != nil {
		return nil, fmt.Errorf("generating access token: %w", err)
	}

	// Generate refresh token.
	refreshToken, err := s.generateToken(userID, userType, roles, TokenTypeRefresh, now)
	if err != nil {
		return nil, fmt.Errorf("generating refresh token: %w", err)
	}

	expiresAt := now.Add(s.config.AccessTokenExpiry)

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.AccessTokenExpiry.Seconds()),
		ExpiresAt:    expiresAt,
	}, nil
}

// GenerateAccessToken generates a new access token for a user.
func (s *Service) GenerateAccessToken(userID ids.UserID, userType enums.UserType, roles []string) (string, error) {
	return s.generateToken(userID, userType, roles, TokenTypeAccess, time.Now())
}

// GenerateRefreshToken generates a new refresh token for a user.
func (s *Service) GenerateRefreshToken(userID ids.UserID, userType enums.UserType, roles []string) (string, error) {
	return s.generateToken(userID, userType, roles, TokenTypeRefresh, time.Now())
}

// generateToken creates a signed JWT token.
func (s *Service) generateToken(userID ids.UserID, userType enums.UserType, roles []string, tokenType TokenType, now time.Time) (string, error) {
	var expiry time.Duration
	switch tokenType {
	case TokenTypeAccess:
		expiry = s.config.AccessTokenExpiry
	case TokenTypeRefresh:
		expiry = s.config.RefreshTokenExpiry
	default:
		return "", fmt.Errorf("invalid token type: %s", tokenType)
	}

	tokenID, err := generateTokenID()
	if err != nil {
		return "", fmt.Errorf("generating token ID: %w", err)
	}

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.Issuer,
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        tokenID,
		},
		UserID:    userID,
		UserType:  userType,
		Roles:     roles,
		TokenType: tokenType,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(s.config.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}

	return signedToken, nil
}

// ValidateToken validates a JWT token and returns its claims.
func (s *Service) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		// Verify the signing method.
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.config.PublicKey, nil
	})

	if err != nil {
		if isExpiredError(err) {
			return nil, errors.TokenExpired("token has expired")
		}
		return nil, errors.TokenInvalid(fmt.Sprintf("invalid token: %v", err))
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.TokenInvalid("invalid token claims")
	}

	// Verify issuer.
	if claims.Issuer != s.config.Issuer {
		return nil, errors.TokenInvalid("invalid token issuer")
	}

	return claims, nil
}

// ValidateAccessToken validates an access token specifically.
func (s *Service) ValidateAccessToken(tokenString string) (*Claims, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != TokenTypeAccess {
		return nil, errors.TokenInvalid("expected access token")
	}

	return claims, nil
}

// ValidateRefreshToken validates a refresh token specifically.
func (s *Service) ValidateRefreshToken(tokenString string) (*Claims, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != TokenTypeRefresh {
		return nil, errors.TokenInvalid("expected refresh token")
	}

	return claims, nil
}

// RefreshTokens generates a new token pair from a valid refresh token.
func (s *Service) RefreshTokens(refreshTokenString string) (*TokenPair, error) {
	claims, err := s.ValidateRefreshToken(refreshTokenString)
	if err != nil {
		return nil, err
	}

	return s.GenerateTokenPair(claims.UserID, claims.UserType, claims.Roles)
}

// isExpiredError checks if the error is due to token expiration.
func isExpiredError(err error) bool {
	return err != nil && (stderrors.Is(err, jwt.ErrTokenExpired) ||
		(err.Error() != "" && contains(err.Error(), "token is expired")))
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// generateTokenID generates a random token ID.
func generateTokenID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateKeyPair generates a new RSA key pair for signing tokens.
// This is primarily useful for testing or initial setup.
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if bits < 2048 {
		bits = 2048
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("generating RSA key: %w", err)
	}
	return privateKey, &privateKey.PublicKey, nil
}

// ExtractBearerToken extracts the token from a Bearer authorization header.
func ExtractBearerToken(authHeader string) (string, error) {
	if authHeader == "" {
		return "", errors.InvalidCredentials("missing authorization header")
	}

	const prefix = "Bearer "
	if len(authHeader) < len(prefix) || authHeader[:len(prefix)] != prefix {
		return "", errors.InvalidCredentials("invalid authorization header format")
	}

	token := authHeader[len(prefix):]
	if token == "" {
		return "", errors.InvalidCredentials("empty token")
	}

	return token, nil
}

// TokenBlacklist is an interface for token revocation support.
// Implementations should store revoked token IDs (jti claims) to prevent reuse.
type TokenBlacklist interface {
	// IsRevoked checks if a token ID has been revoked.
	IsRevoked(ctx context.Context, tokenID string) (bool, error)
	// Revoke adds a token ID to the blacklist.
	// The expiresAt parameter allows implementations to auto-expire entries.
	Revoke(ctx context.Context, tokenID string, expiresAt time.Time) error
	// RevokeAllForUser revokes all tokens for a specific user.
	// This is useful for password changes or account security events.
	RevokeAllForUser(ctx context.Context, userID ids.UserID) error
}

// ServiceWithBlacklist wraps Service with token revocation support.
type ServiceWithBlacklist struct {
	*Service
	blacklist TokenBlacklist
}

// NewServiceWithBlacklist creates a new authentication service with token revocation.
func NewServiceWithBlacklist(cfg Config, blacklist TokenBlacklist) (*ServiceWithBlacklist, error) {
	svc, err := NewService(cfg)
	if err != nil {
		return nil, err
	}
	return &ServiceWithBlacklist{
		Service:   svc,
		blacklist: blacklist,
	}, nil
}

// ValidateToken validates a JWT token and checks if it has been revoked.
func (s *ServiceWithBlacklist) ValidateToken(ctx context.Context, tokenString string) (*Claims, error) {
	claims, err := s.Service.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Check if token has been revoked.
	if s.blacklist != nil {
		revoked, err := s.blacklist.IsRevoked(ctx, claims.ID)
		if err != nil {
			return nil, errors.InternalErrorWrap("checking token revocation", err)
		}
		if revoked {
			return nil, errors.TokenInvalid("token has been revoked")
		}
	}

	return claims, nil
}

// ValidateAccessToken validates an access token and checks revocation.
func (s *ServiceWithBlacklist) ValidateAccessToken(ctx context.Context, tokenString string) (*Claims, error) {
	claims, err := s.ValidateToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != TokenTypeAccess {
		return nil, errors.TokenInvalid("expected access token")
	}

	return claims, nil
}

// ValidateRefreshToken validates a refresh token and checks revocation.
func (s *ServiceWithBlacklist) ValidateRefreshToken(ctx context.Context, tokenString string) (*Claims, error) {
	claims, err := s.ValidateToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != TokenTypeRefresh {
		return nil, errors.TokenInvalid("expected refresh token")
	}

	return claims, nil
}

// RefreshTokens generates a new token pair and revokes the old refresh token.
func (s *ServiceWithBlacklist) RefreshTokens(ctx context.Context, refreshTokenString string) (*TokenPair, error) {
	claims, err := s.ValidateRefreshToken(ctx, refreshTokenString)
	if err != nil {
		return nil, err
	}

	// Revoke the old refresh token.
	if s.blacklist != nil {
		if err := s.blacklist.Revoke(ctx, claims.ID, claims.ExpiresAt.Time); err != nil {
			return nil, errors.InternalErrorWrap("revoking old refresh token", err)
		}
	}

	return s.GenerateTokenPair(claims.UserID, claims.UserType, claims.Roles)
}

// RevokeToken revokes a specific token by its ID.
func (s *ServiceWithBlacklist) RevokeToken(ctx context.Context, tokenString string) error {
	claims, err := s.Service.ValidateToken(tokenString)
	if err != nil {
		return err
	}

	if s.blacklist == nil {
		return nil
	}

	return s.blacklist.Revoke(ctx, claims.ID, claims.ExpiresAt.Time)
}

// RevokeAllUserTokens revokes all tokens for a user (e.g., on password change).
func (s *ServiceWithBlacklist) RevokeAllUserTokens(ctx context.Context, userID ids.UserID) error {
	if s.blacklist == nil {
		return nil
	}
	return s.blacklist.RevokeAllForUser(ctx, userID)
}
