# Stage 1: Build embedded admin UI
FROM node:22-alpine AS ui
# Pin pnpm to a known-good version so corepack doesn't pull a tagged-but-unsigned
# release. v10.x supports `onlyBuiltDependencies` in package.json and does not
# fail the install step on ignored build scripts (newer v11 returns non-zero
# unless explicitly approved, even in non-interactive Docker builds).
RUN corepack enable && corepack prepare pnpm@10.16.1 --activate
WORKDIR /ui
COPY ui/package.json ui/pnpm-lock.yaml* ./
# `--frozen-lockfile` first so verifiable builds win; fall back to a
# lockfile-updating install if the lock is missing.
RUN pnpm install --frozen-lockfile || pnpm install --no-frozen-lockfile
COPY ui/ .
RUN pnpm build

# MPC — single image ships both daemon (mpcd) + CLI (mpc).
# Default entrypoint: mpcd. Override ENTRYPOINT / CMD with `mpc <cmd>` for CLI.
# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine AS builder
# CGO toolchain — required by go-sqlite3 (mattn) so the wallet HTTP API
# can open SQLite. Previously CGO=0 left the driver unregistered and
# /v1/mpc/wallets returned 503; the workaround was seeding wallets into
# TA's user_wallets table out-of-band.
RUN apk add --no-cache git ca-certificates gcc musl-dev sqlite-dev linux-headers
ENV GONOSUMDB=github.com/luxfi/*,github.com/hanzoai/*

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /ui/dist ./ui/dist/

ENV GOEXPERIMENT=runtimesecret
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w -linkmode external -extldflags '-static'" -tags 'sqlite_omit_load_extension' -o mpcd ./cmd/mpcd
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w -linkmode external -extldflags '-static'" -tags 'sqlite_omit_load_extension' -o mpc  ./cmd/mpc

FROM alpine:3.21
# Runtime — statically linked binaries above don't need shared libs, but
# keep ca-certificates + tzdata for HTTPS + log timestamps.
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /app/mpcd /usr/local/bin/mpcd
COPY --from=builder /app/mpc  /usr/local/bin/mpc
EXPOSE 8081 9999 9800
ENTRYPOINT ["mpcd"]
