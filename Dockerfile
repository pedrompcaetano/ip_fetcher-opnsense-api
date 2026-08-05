# Stage 1: Build static binary with Alpine
FROM alpine:3.24 AS builder

# Install build tools, header packages (-dev), and static archives (-static)
RUN apk add --no-cache \
    build-base \
    pkgconf \
    curl-dev \
    curl-static \
    cjson-dev \
    libmicrohttpd-dev \
    openssl-dev \
    openssl-libs-static \
    zlib-dev \
    zlib-static \
    nghttp2-dev \
    nghttp2-static \
    ca-certificates

WORKDIR /build
COPY . .

# Compile static binary
RUN gcc -static main.c -o opnsense_api \
    $(pkg-config --static --cflags --libs libcurl libcjson libmicrohttpd) \
    -pthread

# Stage 2: Zero-overhead runtime container
FROM scratch

# Copy CA certificates for HTTPS requests to OPNsense
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy static binary
COPY --from=builder /build/opnsense_api /opnsense_api

ENTRYPOINT ["/opnsense_api"]
