# Use the official Golang image to build the application
FROM golang:1.20-alpine AS builder

# Create and set the working directory for building your app
WORKDIR /app

# Copy go.mod and go.sum files so you can download dependencies first
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the code
COPY . .

# Build the Go binary
RUN go build -o server

# Now create a small final image
FROM alpine:latest

# Copy the compiled binary from the build step
COPY --from=builder /app/server /server

# Expose port 8080
EXPOSE 8080

# Start the server
CMD ["/server"]
