package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

type UserRole string

const (
	RoleAdmin UserRole = "admin"
	RoleUser  UserRole = "user"
)

type User struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Email     string             `bson:"email" json:"email"`
	Password  string             `bson:"password" json:"-"`
	Role      UserRole           `bson:"role" json:"role"`
	Projects  []string           `bson:"projects" json:"projects"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time          `bson:"updated_at" json:"updated_at"`
}

// NewUser creates a new user with hashed password
func NewUser(email, password string, role UserRole) (*User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	return &User{
		Email:     email,
		Password:  string(hashedPassword),
		Role:      role,
		Projects:  []string{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}

// CheckPassword compares the provided password with the stored hash
func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	return err == nil
}

// AddProject adds a project ID to the user's projects list
func (u *User) AddProject(projectID string) {
	u.Projects = append(u.Projects, projectID)
	u.UpdatedAt = time.Now()
}

// RemoveProject removes a project ID from the user's projects list
func (u *User) RemoveProject(projectID string) {
	for i, id := range u.Projects {
		if id == projectID {
			u.Projects = append(u.Projects[:i], u.Projects[i+1:]...)
			break
		}
	}
	u.UpdatedAt = time.Now()
}
