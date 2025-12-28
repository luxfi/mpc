# Lux MPC — single image ships both daemon (mpcd) + CLI (mpc).
# Default entrypoint: mpcd. Override with `mpc …` for CLI ops.

FROM golang:1.26-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o mpcd ./cmd/mpcd
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o mpc  ./cmd/mpc

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/mpcd /usr/local/bin/mpcd
COPY --from=builder /app/mpc  /usr/local/bin/mpc
EXPOSE 8081 9090
ENTRYPOINT ["mpcd"]
