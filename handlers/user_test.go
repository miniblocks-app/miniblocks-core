package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miniblocks-app/miniblocks-core/db"
	"github.com/miniblocks-app/miniblocks-core/middleware"
	"github.com/miniblocks-app/miniblocks-core/models"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

func setupTestDB(t *testing.T) func() {
	// Connect to test database
	err := db.Connect("mongodb://localhost:27017")
	assert.NoError(t, err)

	// Clean up test data after tests
	return func() {
		ctx := context.Background()
		db.Users.DeleteMany(ctx, bson.M{})
		db.Disconnect()
	}
}

func TestRegister(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	logger := zap.NewNop()
	handler := NewUserHandler(logger)

	tests := []struct {
		name       string
		payload    RegisterRequest
		wantStatus int
	}{
		{
			name: "successful registration",
			payload: RegisterRequest{
				Email:    "test@example.com",
				Password: "password123",
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "duplicate email",
			payload: RegisterRequest{
				Email:    "test@example.com",
				Password: "password123",
			},
			wantStatus: http.StatusConflict,
		},
		{
			name: "empty email",
			payload: RegisterRequest{
				Email:    "",
				Password: "password123",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "empty password",
			payload: RegisterRequest{
				Email:    "test2@example.com",
				Password: "",
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest("POST", "/api/register", bytes.NewBuffer(body))
			w := httptest.NewRecorder()

			handler.Register(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)

			if tt.wantStatus == http.StatusOK {
				var response AuthResponse
				err := json.NewDecoder(w.Body).Decode(&response)
				assert.NoError(t, err)
				assert.NotEmpty(t, response.Token)
				assert.Equal(t, tt.payload.Email, response.User.Email)
				assert.Equal(t, models.RoleUser, response.User.Role)
			}
		})
	}
}

func TestLogin(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	logger := zap.NewNop()
	handler := NewUserHandler(logger)

	// Create a test user
	user, _ := models.NewUser("test@example.com", "password123", models.RoleUser)
	user.ID = primitive.NewObjectID()
	_, err := db.Users.InsertOne(context.Background(), user)
	assert.NoError(t, err)

	tests := []struct {
		name       string
		payload    LoginRequest
		wantStatus int
	}{
		{
			name: "successful login",
			payload: LoginRequest{
				Email:    "test@example.com",
				Password: "password123",
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "wrong password",
			payload: LoginRequest{
				Email:    "test@example.com",
				Password: "wrongpassword",
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "non-existent user",
			payload: LoginRequest{
				Email:    "nonexistent@example.com",
				Password: "password123",
			},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest("POST", "/api/login", bytes.NewBuffer(body))
			w := httptest.NewRecorder()

			handler.Login(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)

			if tt.wantStatus == http.StatusOK {
				var response AuthResponse
				err := json.NewDecoder(w.Body).Decode(&response)
				assert.NoError(t, err)
				assert.NotEmpty(t, response.Token)
				assert.Equal(t, tt.payload.Email, response.User.Email)
			}
		})
	}
}

func TestGetProfile(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	logger := zap.NewNop()
	handler := NewUserHandler(logger)

	// Create a test user
	user, _ := models.NewUser("test@example.com", "password123", models.RoleUser)
	user.ID = primitive.NewObjectID()
	_, err := db.Users.InsertOne(context.Background(), user)
	assert.NoError(t, err)

	// Generate token for the user
	token, err := middleware.GenerateToken(user)
	assert.NoError(t, err)

	tests := []struct {
		name       string
		token      string
		wantStatus int
	}{
		{
			name:       "successful profile retrieval",
			token:      token,
			wantStatus: http.StatusOK,
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
			req := httptest.NewRequest("GET", "/api/profile", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			w := httptest.NewRecorder()

			handler.GetProfile(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)

			if tt.wantStatus == http.StatusOK {
				var response models.User
				err := json.NewDecoder(w.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, user.Email, response.Email)
				assert.Equal(t, user.Role, response.Role)
			}
		})
	}
}

func TestUpdateProfile(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	logger := zap.NewNop()
	handler := NewUserHandler(logger)

	// Create a test user
	user, _ := models.NewUser("test@example.com", "password123", models.RoleUser)
	user.ID = primitive.NewObjectID()
	_, err := db.Users.InsertOne(context.Background(), user)
	assert.NoError(t, err)

	// Generate token for the user
	token, err := middleware.GenerateToken(user)
	assert.NoError(t, err)

	tests := []struct {
		name       string
		token      string
		payload    map[string]string
		wantStatus int
	}{
		{
			name:  "update email",
			token: token,
			payload: map[string]string{
				"email": "newemail@example.com",
			},
			wantStatus: http.StatusOK,
		},
		{
			name:  "update password",
			token: token,
			payload: map[string]string{
				"password": "newpassword123",
			},
			wantStatus: http.StatusOK,
		},
		{
			name:  "update both email and password",
			token: token,
			payload: map[string]string{
				"email":    "newemail2@example.com",
				"password": "newpassword456",
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing token",
			token:      "",
			payload:    map[string]string{},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid token",
			token:      "invalid-token",
			payload:    map[string]string{},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest("PUT", "/api/profile/update", bytes.NewBuffer(body))
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			w := httptest.NewRecorder()

			handler.UpdateProfile(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)

			if tt.wantStatus == http.StatusOK {
				// Verify the update in the database
				var updatedUser models.User
				err := db.Users.FindOne(context.Background(), bson.M{"_id": user.ID}).Decode(&updatedUser)
				assert.NoError(t, err)

				if email, ok := tt.payload["email"]; ok {
					assert.Equal(t, email, updatedUser.Email)
				}
				if password, ok := tt.payload["password"]; ok {
					assert.True(t, updatedUser.CheckPassword(password))
				}
			}
		})
	}
}
