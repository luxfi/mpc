# Stage 1: Build embedded admin UI
FROM node:22-alpine AS ui
RUN corepack enable && corepack prepare pnpm@latest --activate
WORKDIR /ui
COPY ui/package.json ui/pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile 2>/dev/null || pnpm install
COPY ui/ .
RUN pnpm build

# Lux MPC — single image ships both daemon (mpcd) + CLI (mpc).
# Default entrypoint: mpcd. Override ENTRYPOINT / CMD with `mpc <cmd>` for CLI.
# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder
RUN apk add --no-cache git ca-certificates
ARG GITHUB_TOKEN
RUN git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"
ENV GOPRIVATE=github.com/luxfi/*,github.com/hanzoai/*
ENV GONOSUMCHECK=*
ENV GONOSUMDB=*
ENV GOPROXY=direct

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /ui/dist ./ui/dist/

ENV GOEXPERIMENT=runtimesecret
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o mpcd ./cmd/mpcd
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o mpc  ./cmd/mpc

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /app/mpcd /usr/local/bin/mpcd
COPY --from=builder /app/mpc  /usr/local/bin/mpc
EXPOSE 8081 9651 9800
ENTRYPOINT ["mpcd"]
