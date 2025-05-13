package db

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

var (
	client   *mongo.Client
	database *mongo.Database
	Users    *mongo.Collection
	Projects *mongo.Collection
)

// Connect establishes a connection to MongoDB
func Connect(uri string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI(uri)
	var err error
	client, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		return err
	}

	// Ping the database
	if err = client.Ping(ctx, readpref.Primary()); err != nil {
		return err
	}

	database = client.Database("miniblocks")
	Users = database.Collection("users")
	Projects = database.Collection("projects")

	log.Println("Connected to MongoDB!")
	return nil
}

// Disconnect closes the MongoDB connection
func Disconnect() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return client.Disconnect(ctx)
}

// GetDatabase returns the database instance
func GetDatabase() *mongo.Database {
	return database
}

// GetClient returns the MongoDB client
func GetClient() *mongo.Client {
	return client
}
