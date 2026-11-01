# Nodetide Go Docker Image
# Multi-stage build for smaller final image

# Build stage
FROM golang:1.27-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY golang/go.mod golang/go.sum* ./
RUN go mod download

# Copy web client for embedding
COPY web/ ./web/

# Copy source code (main package plus subpackages such as auth/)
COPY golang/ ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o nodetide .

# Runtime stage
FROM alpine:3.24

RUN apk --no-cache add ca-certificates && \
    adduser -D -s /bin/sh nodetide

WORKDIR /app

COPY --from=builder /build/nodetide .

# Create data directory
RUN mkdir -p /data && chown nodetide:nodetide /data

USER nodetide

ENV PORT=4557

EXPOSE 4557

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:4557/api/identities || exit 1

CMD ["./nodetide"]
