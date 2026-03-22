# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

RUN apk add --no-cache git ca-certificates

ARG GITHUB_TOKEN
RUN git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"
ENV GOPRIVATE=github.com/luxfi/*,github.com/hanzoai/*

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ENV GOEXPERIMENT=runtimesecret
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o mpcd ./cmd/mpcd

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/mpcd /usr/local/bin/mpcd
EXPOSE 8081 9651 9800
ENTRYPOINT ["mpcd"]
