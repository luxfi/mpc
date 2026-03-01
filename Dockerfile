FROM golang:1.26-alpine AS builder
ARG TARGETARCH
RUN apk add --no-cache git make
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor/ vendor/
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build -mod=vendor -o /mpcd ./cmd/mpcd/

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /mpcd /usr/local/bin/mpcd
EXPOSE 8081
ENTRYPOINT ["mpcd"]
