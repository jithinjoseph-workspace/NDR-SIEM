
FROM rust:latest

WORKDIR /app

COPY ndr-engine ./ndr-engine

WORKDIR /app/ndr-engine

RUN cargo build --release

CMD ["./target/release/ndr-engine"]
