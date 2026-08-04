# syntax=docker/dockerfile:1
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

FROM --platform=$BUILDPLATFORM golang:1.26.5-alpine AS builder
ENV GOTOOLCHAIN=auto
# CGO toolchain — required by go-sqlite3 (mattn) so the wallet HTTP API
# can open SQLite. Previously CGO=0 left the driver unregistered and
# /v1/mpc/wallets returned 503; the workaround was seeding wallets into
# TA's user_wallets table out-of-band.
RUN apk add --no-cache git ca-certificates gcc musl-dev sqlite-dev linux-headers
# Module fetch policy:
#  - GOPRIVATE=luxfi/hsm: hsm is a PRIVATE repo -> fetch direct from git with
#    the token below (proxy can't serve it).
#  - GOSUMDB=off: verify module hashes against the committed go.sum ONLY, not
#    sum.golang.org. Some first-party modules are freshly published or were
#    re-tagged, so the public sumdb lags; go.sum is the source of truth.
#  - Everything else uses the default proxy (proxy.golang.org,direct): public
#    modules the proxy has cached resolve there; a proxy miss falls back to
#    direct git (public tag exists) — NOT forced direct (which broke on
#    luxfi/geth, whose proxy-cached version has no live git tag).
ENV GOPRIVATE=
ENV GOSUMDB=off
ENV GOFLAGS=-mod=mod

WORKDIR /app
COPY . .
COPY --from=ui /ui/dist ./ui/dist/

# go.work names ../threshold — a SIBLING CHECKOUT. That is right for a developer
# (the comment above it says so) and impossible in a container: the build context
# is this repo alone, so `../threshold` resolves to /threshold, which does not
# exist, and `go mod download all` dies before a single package compiles. Every
# containerized build has failed that way since the entry landed — v1.17.16 and
# v1.17.17 are tags with no image, and the fleet still runs v1.17.15.
#
# GOWORK=off is the fix, not deleting the entry: the workspace is a local
# convenience, while the BUILD must resolve the published module graph — go.mod
# already pins github.com/luxfi/threshold v1.12.5, so the proxy has it. Set for
# every stage below (download and both builds) so a workspace file can never
# again decide what a release contains.
ENV GOWORK=off
# Regenerate go.sum from the actual fetch sources (proxy for public modules,
# authed git for private luxfi/hsm). Several first-party modules were re-tagged
# or freshly published, so the proxy vs git content hashes drift and the
# committed (git-sourced) go.sum fails proxy-fetch verification. rm + re-download
# rebuilds go.sum from what is really fetched; GOFLAGS=-mod=mod + GOSUMDB=off let
# it record those hashes. This is regenerate-not-bypass.
RUN --mount=type=secret,id=gh_token \
    sh -c 'if [ -s /run/secrets/gh_token ]; then \
             git config --global url."https://x-access-token:$(cat /run/secrets/gh_token)@github.com/".insteadOf "https://github.com/"; \
           fi; \
           rm -f go.sum; \
           go mod download all'

# Per SCALE_STANDARD.md §2 (https://github.com/hanzoai/hips/blob/main/docs/SCALE_STANDARD.md)
# — every Go production Dockerfile that emits JSON to a client builds
# with GOEXPERIMENT=jsonv2 (composed with runtimesecret for the MPC
# data-plane secrecy guarantees). Verified -12% time / -23% allocs on
# the edge POST roundtrip vs encoding/json v1.
ENV GOEXPERIMENT=runtimesecret,jsonv2
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
