package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/miniblocks-app/miniblocks-core/models"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func TestAuthMiddleware(t *testing.T) {
	// Create a test user
	user := &models.User{
		ID:    primitive.NewObjectID(),
		Email: "test@example.com",
		Role:  models.RoleUser,
	}

	// Generate a valid token
	token, err := GenerateToken(user)
	assert.NoError(t, err)

	// Create a test handler that checks the context
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := GetUserFromContext(r.Context())
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		assert.Equal(t, user.ID, claims.UserID)
		assert.Equal(t, user.Email, claims.Email)
		assert.Equal(t, user.Role, claims.Role)
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name       string
		token      string
		wantStatus int
	}{
		{
			name:       "valid token",
			token:      token,
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing token",
			token:      "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid token format",
			token:      "invalid-token",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid bearer format",
			token:      "Bearer",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			w := httptest.NewRecorder()

			AuthMiddleware(testHandler).ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

func TestAdminMiddleware(t *testing.T) {
	// Create test users
	adminUser := &models.User{
		ID:    primitive.NewObjectID(),
		Email: "admin@example.com",
		Role:  models.RoleAdmin,
	}

	regularUser := &models.User{
		ID:    primitive.NewObjectID(),
		Email: "user@example.com",
		Role:  models.RoleUser,
	}

	// Generate tokens
	adminToken, err := GenerateToken(adminUser)
	assert.NoError(t, err)

	userToken, err := GenerateToken(regularUser)
	assert.NoError(t, err)

	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name       string
		token      string
		wantStatus int
	}{
		{
			name:       "admin access",
			token:      adminToken,
			wantStatus: http.StatusOK,
		},
		{
			name:       "regular user access",
			token:      userToken,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "missing token",
			token:      "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid token",
			token:      "invalid-token",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			w := httptest.NewRecorder()

			// Chain the middlewares
			AuthMiddleware(AdminMiddleware(testHandler)).ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

func TestTokenExpiration(t *testing.T) {
	// Create a test user
	user := &models.User{
		ID:    primitive.NewObjectID(),
		Email: "test@example.com",
		Role:  models.RoleUser,
	}

	// Generate a token with a very short expiration
	claims := &Claims{
		UserID: user.ID,
		Email:  user.Email,
		Role:   user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)), // Expired
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	expiredToken, err := token.SignedString(jwtSecret)
	assert.NoError(t, err)

	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken)
	w := httptest.NewRecorder()

	AuthMiddleware(testHandler).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
