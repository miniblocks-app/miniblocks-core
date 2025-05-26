package main

import (
	"net/http"
	"os"

	"github.com/miniblocks-app/miniblocks-core/db"
	"github.com/miniblocks-app/miniblocks-core/handlers"
	"github.com/miniblocks-app/miniblocks-core/logger"
	"github.com/miniblocks-app/miniblocks-core/middleware"
	"github.com/miniblocks-app/miniblocks-core/utils"
	"go.uber.org/zap"
)

func main() {
	defer func() {
		_ = logger.Sync()
	}()

	logger.Initialize()
	log := logger.Get()

	mongoURI := os.Getenv("MONGODB_URI")
	if mongoURI == "" {
		mongoURI = "mongodb+srv://mrmihiraj:miniblocks@core-cluster.bnpvs.mongodb.net/?retryWrites=true&w=majority&appName=core-cluster"
	}
	if err := db.Connect(mongoURI); err != nil {
		log.Fatal("Failed to connect to MongoDB", zap.Error(err))
	}
	defer func() {
		err := db.Disconnect()
		if err != nil {
			log.Error("Failed to disconnect from MongoDB", zap.Error(err))
		}
	}()

	// Initialize handlers
	userHandler := handlers.NewUserHandler(log)

	// Setup routes
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/api/register", middleware.CorsMiddleware(userHandler.Register))
	mux.HandleFunc("/api/login", middleware.CorsMiddleware(userHandler.Login))

	// Protected routes
	mux.HandleFunc("/api/profile", middleware.CorsMiddleware(middleware.AuthMiddleware(userHandler.GetProfile)))
	mux.HandleFunc("/api/profile/update", middleware.CorsMiddleware(middleware.AuthMiddleware(userHandler.UpdateProfile)))
	mux.HandleFunc("/upload", middleware.CorsMiddleware(utils.HandleUpload))
	mux.HandleFunc("/compile", middleware.CorsMiddleware(utils.HandleCompile))

	log.Info("Starting server on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal("Failed to start server", zap.Error(err))
	}
}
