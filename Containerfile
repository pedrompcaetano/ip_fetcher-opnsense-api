# Stage 1: Build binary dynamically
FROM alpine:3.24 AS builder

RUN apk add --no-cache \
    build-base \
    pkgconf \
    curl-dev \
    cjson-dev \
    libmicrohttpd-dev

WORKDIR /build
COPY . .

# Compile dynamically against Alpine headers
RUN gcc main.c -o opnsense_api \
    $(pkg-config --cflags --libs libcurl libcjson libmicrohttpd) \
    -pthread

# Stage 2: Minimal Runtime (~10 MB total, zero vulnerability noise)
FROM alpine:3.24

# Install only the runtime dynamic shared libraries
RUN apk add --no-cache \
    libcurl \
    cjson \
    libmicrohttpd \
    ca-certificates

COPY --from=builder /build/opnsense_api /usr/local/bin/opnsense_api

ENTRYPOINT ["/usr/local/bin/opnsense_api"]
