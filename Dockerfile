# 1) Use the official Golang image to build the application
FROM golang:1.20-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first to cache module downloads
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the Go binary
RUN go build -o server

# 2) Create a minimal final image
FROM alpine:3.17
WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/server /app/server

# EXPOSE is optional for Cloud Run,
# but helps local testing (must match the port in your code).
EXPOSE 8080

# Start the server
CMD ["/app/server"]
