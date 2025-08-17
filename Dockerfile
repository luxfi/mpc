# Build stage
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /build

# Copy source code
COPY . .

# Create a Docker-compatible go.mod without version restrictions
RUN cp go.mod go.mod.backup && \
    echo "module github.com/luxfi/mpc" > go.mod.tmp && \
    echo "" >> go.mod.tmp && \
    echo "go 1.23" >> go.mod.tmp && \
    echo "" >> go.mod.tmp && \
    grep -v "^go " go.mod.backup | grep -v "^module " >> go.mod.tmp && \
    mv go.mod.tmp go.mod

# Download dependencies (ignoring version errors)
RUN go mod tidy || true

# Build the binaries
RUN go build -o lux-mpc ./cmd/lux-mpc
RUN go build -o lux-mpc-cli ./cmd/lux-mpc-cli  
RUN go build -o lux-mpc-bridge ./cmd/lux-mpc-bridge || true

# Runtime stage
FROM alpine:latest

RUN apk add --no-cache ca-certificates curl bash

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /build/lux-mpc /usr/local/bin/
COPY --from=builder /build/lux-mpc-cli /usr/local/bin/
COPY --from=builder /build/lux-mpc-bridge /usr/local/bin/ 2>/dev/null || true

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
CMD ["lux-mpc", "start", "--config", "/app/config.yaml"]