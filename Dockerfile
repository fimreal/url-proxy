# syntax=docker/dockerfile:1

# Stage 1: Build static binary
FROM golang:1.22-alpine AS builder

WORKDIR /build

COPY go.mod ./
# Copy source files
COPY main.go ./

# Compile statically linked, stripped binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o url-proxy .

# Stage 2: Minimal runtime image
FROM alpine:3.19

# Install CA certificates for HTTPS upstream requests and tzdata for logging
RUN apk --no-cache add ca-certificates tzdata

# Create non-root unprivileged user
USER 65534:65534

WORKDIR /app
COPY --from=builder /build/url-proxy /app/url-proxy

# Default configuration environment variables
ENV PORT=8080 \
    ALLOW_DOMAINS="" \
    BLOCK_DOMAINS="" \
    BLOCK_PRIVATE_IPS=true \
    MAX_REDIRECTS=10 \
    BUFFER_SIZE_KB=32

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=3s --retries=3 \
  CMD ["/app/url-proxy", "-healthcheck"] || exit 0

ENTRYPOINT ["/app/url-proxy"]
