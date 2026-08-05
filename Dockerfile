# Stage 1: Build Environment
FROM debian:trixie AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    libcurl4-openssl-dev \
    libcjson-dev \
    libmicrohttpd-dev \
    pkg-config

WORKDIR /src
COPY main.c .

# Compile dynamically (removed -static and extra manual link flags)
RUN gcc -O2 -o opnsense_api main.c -lmicrohttpd -lcjson -lcurl

# Stage 2: Minimal Runtime Environment
FROM gcr.io/distroless/cc-debian13

# Install only the necessary runtime libraries
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libmicrohttpd12t64 \
    libcjson1 \
    libcurl4t64 && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -u 10001 -M -s /sbin/nologin appuser

COPY --from=builder /src/opnsense_api /opnsense_api

EXPOSE 8000

USER 10001:10001
CMD ["/opnsense_api"]
