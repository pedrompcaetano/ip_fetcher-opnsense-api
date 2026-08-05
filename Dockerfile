# Stage 1: Build static binary
FROM debian:13-slim AS builder

# Install build tools and static development libraries (.a files)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libcjson-dev \
    libcurl4-openssl-dev \
    libmicrohttpd-dev \
    libssl-dev \
    zlib1g-dev \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

# Compile using -static and resolve transitive dependencies via pkg-config
RUN gcc -static main.c -o opnsense_api \
    $(pkg-config --static --cflags --libs libcurl libcjson libmicrohttpd) \
    -pthread

# Stage 2: Zero-overhead container (Zero OS vulnerabilities)
FROM scratch

# Copy root CA certificates (required if making HTTPS requests to OPNsense)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the static binary
COPY --from=builder /build/opnsense_api /opnsense_api

ENTRYPOINT ["/opnsense_api"]
