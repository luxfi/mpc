# Build stage
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binaries
RUN go build -o mpcd ./cmd/mpcd
RUN go build -o lux-mpc-cli ./cmd/lux-mpc-cli

# Runtime stage
FROM alpine:latest

RUN apk add --no-cache ca-certificates curl bash

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /build/mpcd /usr/local/bin/
COPY --from=builder /build/lux-mpc-cli /usr/local/bin/

# Copy config templates
COPY config.yaml.template /app/
COPY peers.json /app/

# Create data and log directories
RUN mkdir -p /data/mpc /app/logs /app/identity

# Expose ports
EXPOSE 6000 8080 9090

# Health check
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Default command
CMD ["mpcd", "start", "--config", "/app/config.yaml"]