#!/bin/bash

# Format your code
go fmt ./...

# Check for errors and warnings
go vet ./...

# Check with linter
golangci-lint run

# Run tests ...
go test -v ./...

