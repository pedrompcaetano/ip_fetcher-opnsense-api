# Stage 1: Build static binary with Alpine
FROM alpine:3.20 AS builder

# Install build tools and explicit static library packages
RUN apk add --no-cache \
    build-base \
    pkgconf \
    curl-static \
    openssl-libs-static \
    zlib-static \
    nghttp2-static \
    libmicrohttpd-dev \
    cjson-dev \
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
