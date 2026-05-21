
FROM rust:latest

WORKDIR /app

COPY ndr-engine ./ndr-engine

WORKDIR /app/ndr-engine

RUN apt-get update && apt-get install -y \
    cmake libssl-dev pkg-config \
    libsasl2-dev build-essential libcurl4-openssl-dev \
    docker.io curl

RUN cargo build --release

CMD ["./target/release/ndr-engine"]
