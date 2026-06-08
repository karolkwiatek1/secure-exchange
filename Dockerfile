FROM golang:alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/bin/ttp ./cmd/ttp
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/bin/server ./cmd/server

FROM alpine:latest
WORKDIR /app
RUN apk add --no-cache wget
COPY --from=builder /app/bin /app/bin
RUN mkdir -p /app/shared_files