package auth

import (
	"crypto/rsa"
	"testing"
	"time"

	"github.com/Dorico-Dynamics/txova-go-types/enums"
	"github.com/Dorico-Dynamics/txova-go-types/ids"

	"github.com/Dorico-Dynamics/txova-go-core/errors"
)

// testKeyPair holds a pre-generated key pair for testing.
var testKeyPair struct {
	private *rsa.PrivateKey
	public  *rsa.PublicKey
}

func init() {
	var err error
	testKeyPair.private, testKeyPair.public, err = GenerateKeyPair(2048)
	if err != nil {
		panic("failed to generate test key pair: " + err.Error())
	}
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	svc, err := NewService(Config{
		PrivateKey:         testKeyPair.private,
		PublicKey:          testKeyPair.public,
		Issuer:             "test-issuer",
		AccessTokenExpiry:  1 * time.Hour,
		RefreshTokenExpiry: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}
	return svc
}

func TestNewService(t *testing.T) {
	t.Parallel()

	t.Run("valid config", func(t *testing.T) {
		t.Parallel()
		svc, err := NewService(Config{
			PrivateKey: testKeyPair.private,
		})
		if err != nil {
			t.Fatalf("NewService() error = %v", err)
		}
		if svc == nil {
			t.Fatal("NewService() returned nil")
		}
	})

	t.Run("missing private key", func(t *testing.T) {
		t.Parallel()
		_, err := NewService(Config{})
		if err == nil {
			t.Fatal("NewService() should fail without private key")
		}
	})

	t.Run("defaults applied", func(t *testing.T) {
		t.Parallel()
		svc, err := NewService(Config{
			PrivateKey: testKeyPair.private,
		})
		if err != nil {
			t.Fatalf("NewService() error = %v", err)
		}
		if svc.config.Issuer != "txova" {
			t.Errorf("default issuer = %v, want txova", svc.config.Issuer)
		}
		if svc.config.AccessTokenExpiry != 24*time.Hour {
			t.Errorf("default access expiry = %v, want 24h", svc.config.AccessTokenExpiry)
		}
		if svc.config.RefreshTokenExpiry != 30*24*time.Hour {
			t.Errorf("default refresh expiry = %v, want 720h", svc.config.RefreshTokenExpiry)
		}
	})
}

func TestGenerateTokenPair(t *testing.T) {
	t.Parallel()

	svc := newTestService(t)
	userID := ids.MustNewUserID()
	userType := enums.UserTypeRider
	roles := []string{"rider", "verified"}

	pair, err := svc.GenerateTokenPair(userID, userType, roles)
	if err != nil {
		t.Fatalf("GenerateTokenPair() error = %v", err)
	}

	if pair.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}
	if pair.RefreshToken == "" {
		t.Error("RefreshToken should not be empty")
	}
	if pair.TokenType != "Bearer" {
		t.Errorf("TokenType = %v, want Bearer", pair.TokenType)
	}
	if pair.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %v, want 3600", pair.ExpiresIn)
	}
	if pair.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should not be zero")
	}

	// Verify tokens are different.
	if pair.AccessToken == pair.RefreshToken {
		t.Error("AccessToken and RefreshToken should be different")
	}
}

func TestGenerateAccessToken(t *testing.T) {
	t.Parallel()

	svc := newTestService(t)
	userID := ids.MustNewUserID()
	userType := enums.UserTypeDriver
	roles := []string{"driver"}

	token, err := svc.GenerateAccessToken(userID, userType, roles)
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	if token == "" {
		t.Error("token should not be empty")
	}

	// Validate the token.
	claims, err := svc.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("ValidateAccessToken() error = %v", err)
	}

	if claims.UserID.String() != userID.String() {
		t.Errorf("UserID = %v, want %v", claims.UserID, userID)
	}
	if claims.UserType != userType {
		t.Errorf("UserType = %v, want %v", claims.UserType, userType)
	}
	if claims.TokenType != TokenTypeAccess {
		t.Errorf("TokenType = %v, want %v", claims.TokenType, TokenTypeAccess)
	}
}

func TestGenerateRefreshToken(t *testing.T) {
	t.Parallel()

	svc := newTestService(t)
	userID := ids.MustNewUserID()
	userType := enums.UserTypeAdmin
	roles := []string{"admin", "super_admin"}

	token, err := svc.GenerateRefreshToken(userID, userType, roles)
	if err != nil {
		t.Fatalf("GenerateRefreshToken() error = %v", err)
	}

	if token == "" {
		t.Error("token should not be empty")
	}

	// Validate the token.
	claims, err := svc.ValidateRefreshToken(token)
	if err != nil {
		t.Fatalf("ValidateRefreshToken() error = %v", err)
	}

	if claims.UserID.String() != userID.String() {
		t.Errorf("UserID = %v, want %v", claims.UserID, userID)
	}
	if claims.TokenType != TokenTypeRefresh {
		t.Errorf("TokenType = %v, want %v", claims.TokenType, TokenTypeRefresh)
	}
	if len(claims.Roles) != 2 {
		t.Errorf("Roles length = %v, want 2", len(claims.Roles))
	}
}

func TestValidateToken(t *testing.T) {
	t.Parallel()

	svc := newTestService(t)
	userID := ids.MustNewUserID()

	t.Run("valid token", func(t *testing.T) {
		t.Parallel()
		token, _ := svc.GenerateAccessToken(userID, enums.UserTypeRider, nil)
		claims, err := svc.ValidateToken(token)
		if err != nil {
			t.Fatalf("ValidateToken() error = %v", err)
		}
		if claims.UserID.String() != userID.String() {
			t.Errorf("UserID = %v, want %v", claims.UserID, userID)
		}
	})

	t.Run("invalid token format", func(t *testing.T) {
		t.Parallel()
		_, err := svc.ValidateToken("not-a-valid-token")
		if err == nil {
			t.Fatal("ValidateToken() should fail with invalid token")
		}
		if !errors.IsUnauthorized(err) {
			t.Errorf("error should be unauthorized, got: %v", err)
		}
	})

	t.Run("empty token", func(t *testing.T) {
		t.Parallel()
		_, err := svc.ValidateToken("")
		if err == nil {
			t.Fatal("ValidateToken() should fail with empty token")
		}
	})

	t.Run("tampered token", func(t *testing.T) {
		t.Parallel()
		token, _ := svc.GenerateAccessToken(userID, enums.UserTypeRider, nil)
		// Tamper with the token.
		tamperedToken := token[:len(token)-5] + "XXXXX"
		_, err := svc.ValidateToken(tamperedToken)
		if err == nil {
			t.Fatal("ValidateToken() should fail with tampered token")
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		t.Parallel()
		// Create a service with different issuer.
		otherSvc, _ := NewService(Config{
			PrivateKey: testKeyPair.private,
			Issuer:     "other-issuer",
		})
		token, _ := otherSvc.GenerateAccessToken(userID, enums.UserTypeRider, nil)

		// Validate with original service.
		_, err := svc.ValidateToken(token)
		if err == nil {
			t.Fatal("ValidateToken() should fail with wrong issuer")
		}
	})
}

func TestValidateAccessToken_WrongType(t *testing.T) {
	t.Parallel()

	svc := newTestService(t)
	userID := ids.MustNewUserID()

	// Generate a refresh token.
	refreshToken, _ := svc.GenerateRefreshToken(userID, enums.UserTypeRider, nil)

	// Try to validate as access token.
	_, err := svc.ValidateAccessToken(refreshToken)
	if err == nil {
		t.Fatal("ValidateAccessToken() should fail with refresh token")
	}
	if !errors.IsUnauthorized(err) {
		t.Errorf("error should be unauthorized, got: %v", err)
	}
}

func TestValidateRefreshToken_WrongType(t *testing.T) {
	t.Parallel()

	svc := newTestService(t)
	userID := ids.MustNewUserID()

	// Generate an access token.
	accessToken, _ := svc.GenerateAccessToken(userID, enums.UserTypeRider, nil)

	// Try to validate as refresh token.
	_, err := svc.ValidateRefreshToken(accessToken)
	if err == nil {
		t.Fatal("ValidateRefreshToken() should fail with access token")
	}
}

func TestRefreshTokens(t *testing.T) {
	t.Parallel()

	svc := newTestService(t)
	userID := ids.MustNewUserID()
	userType := enums.UserTypeDriver
	roles := []string{"driver", "verified"}

	// Generate initial token pair.
	originalPair, err := svc.GenerateTokenPair(userID, userType, roles)
	if err != nil {
		t.Fatalf("GenerateTokenPair() error = %v", err)
	}

	// Refresh tokens.
	newPair, err := svc.RefreshTokens(originalPair.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshTokens() error = %v", err)
	}

	// Verify new tokens are different.
	if newPair.AccessToken == originalPair.AccessToken {
		t.Error("new AccessToken should be different from original")
	}
	if newPair.RefreshToken == originalPair.RefreshToken {
		t.Error("new RefreshToken should be different from original")
	}

	// Verify new tokens are valid and contain same claims.
	newClaims, err := svc.ValidateAccessToken(newPair.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken() error = %v", err)
	}

	if newClaims.UserID.String() != userID.String() {
		t.Errorf("UserID = %v, want %v", newClaims.UserID, userID)
	}
	if newClaims.UserType != userType {
		t.Errorf("UserType = %v, want %v", newClaims.UserType, userType)
	}
	if len(newClaims.Roles) != len(roles) {
		t.Errorf("Roles length = %v, want %v", len(newClaims.Roles), len(roles))
	}
}

func TestRefreshTokens_WithAccessToken(t *testing.T) {
	t.Parallel()

	svc := newTestService(t)
	userID := ids.MustNewUserID()

	// Generate access token.
	accessToken, _ := svc.GenerateAccessToken(userID, enums.UserTypeRider, nil)

	// Try to refresh with access token.
	_, err := svc.RefreshTokens(accessToken)
	if err == nil {
		t.Fatal("RefreshTokens() should fail with access token")
	}
}

func TestExpiredToken(t *testing.T) {
	t.Parallel()

	// Create service with very short expiry.
	svc, err := NewService(Config{
		PrivateKey:        testKeyPair.private,
		AccessTokenExpiry: 1 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	userID := ids.MustNewUserID()
	token, _ := svc.GenerateAccessToken(userID, enums.UserTypeRider, nil)

	// Wait for token to expire.
	time.Sleep(10 * time.Millisecond)

	_, err = svc.ValidateToken(token)
	if err == nil {
		t.Fatal("ValidateToken() should fail with expired token")
	}

	// Check it's specifically a token expired error.
	appErr := errors.AsAppError(err)
	if appErr == nil || appErr.Code() != errors.CodeTokenExpired {
		t.Errorf("error should be TOKEN_EXPIRED, got: %v", err)
	}
}

func TestGenerateKeyPair(t *testing.T) {
	t.Parallel()

	t.Run("valid bits", func(t *testing.T) {
		t.Parallel()
		private, public, err := GenerateKeyPair(2048)
		if err != nil {
			t.Fatalf("GenerateKeyPair() error = %v", err)
		}
		if private == nil {
			t.Error("private key should not be nil")
		}
		if public == nil {
			t.Error("public key should not be nil")
		}
	})

	t.Run("minimum bits enforced", func(t *testing.T) {
		t.Parallel()
		private, _, err := GenerateKeyPair(1024) // Should be upgraded to 2048.
		if err != nil {
			t.Fatalf("GenerateKeyPair() error = %v", err)
		}
		if private.N.BitLen() < 2048 {
			t.Errorf("key size = %v bits, want at least 2048", private.N.BitLen())
		}
	})
}

func TestExtractBearerToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		header      string
		wantToken   string
		wantErr     bool
		errContains string
	}{
		{
			name:      "valid bearer token",
			header:    "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test",
			wantToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test",
			wantErr:   false,
		},
		{
			name:        "missing header",
			header:      "",
			wantErr:     true,
			errContains: "missing",
		},
		{
			name:        "wrong scheme",
			header:      "Basic dXNlcjpwYXNz",
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name:        "empty token",
			header:      "Bearer ",
			wantErr:     true,
			errContains: "empty",
		},
		{
			name:        "lowercase bearer",
			header:      "bearer token",
			wantErr:     true,
			errContains: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			token, err := ExtractBearerToken(tt.header)

			if tt.wantErr {
				if err == nil {
					t.Fatal("ExtractBearerToken() should return error")
				}
				if !errors.IsUnauthorized(err) {
					t.Errorf("error should be unauthorized, got: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("ExtractBearerToken() error = %v", err)
				}
				if token != tt.wantToken {
					t.Errorf("token = %v, want %v", token, tt.wantToken)
				}
			}
		})
	}
}

func TestClaimsFields(t *testing.T) {
	t.Parallel()

	svc := newTestService(t)
	userID := ids.MustNewUserID()
	userType := enums.UserTypeBoth
	roles := []string{"rider", "driver"}

	token, _ := svc.GenerateAccessToken(userID, userType, roles)
	claims, err := svc.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	// Verify all claims are populated.
	if claims.ID == "" {
		t.Error("token ID (jti) should not be empty")
	}
	if claims.Issuer != "test-issuer" {
		t.Errorf("Issuer = %v, want test-issuer", claims.Issuer)
	}
	if claims.Subject != userID.String() {
		t.Errorf("Subject = %v, want %v", claims.Subject, userID.String())
	}
	if claims.IssuedAt == nil {
		t.Error("IssuedAt should not be nil")
	}
	if claims.ExpiresAt == nil {
		t.Error("ExpiresAt should not be nil")
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	if cfg.Issuer != "txova" {
		t.Errorf("Issuer = %v, want txova", cfg.Issuer)
	}
	if cfg.AccessTokenExpiry != 24*time.Hour {
		t.Errorf("AccessTokenExpiry = %v, want 24h", cfg.AccessTokenExpiry)
	}
	if cfg.RefreshTokenExpiry != 30*24*time.Hour {
		t.Errorf("RefreshTokenExpiry = %v, want 720h", cfg.RefreshTokenExpiry)
	}
}

func TestTokenUniqueIDs(t *testing.T) {
	t.Parallel()

	svc := newTestService(t)
	userID := ids.MustNewUserID()

	// Generate multiple tokens and verify they have unique IDs.
	ids := make(map[string]bool)
	for range 10 {
		token, _ := svc.GenerateAccessToken(userID, enums.UserTypeRider, nil)
		claims, _ := svc.ValidateToken(token)
		if ids[claims.ID] {
			t.Errorf("duplicate token ID: %s", claims.ID)
		}
		ids[claims.ID] = true
	}
}
