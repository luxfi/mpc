FROM golang:1.25-alpine AS builder
RUN apk add --no-cache git make
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /mpcd ./cmd/mpcd/

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /mpcd /usr/local/bin/mpcd
COPY --from=builder /src/pkg/db/migrations /migrations
EXPOSE 8081
ENTRYPOINT ["mpcd"]
