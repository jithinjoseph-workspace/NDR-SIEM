
# ── Build stage ────────────────────────────────────────────────────
FROM rust:latest AS builder

WORKDIR /app

ARG CACHEBUST=1

COPY ndr-engine ./ndr-engine

WORKDIR /app/ndr-engine

RUN apt-get update && apt-get install -y \
    cmake libssl-dev pkg-config \
    libsasl2-dev build-essential libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo build --release

# ── Runtime stage ──────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates libssl3 libsasl2-2 libcurl4 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/ndr-engine/target/release/ndr-engine .

CMD ["./ndr-engine"]
