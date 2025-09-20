FROM rust:1.89.0-trixie as builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/timeline-backend /app/timeline-backend
COPY static ./static

EXPOSE 8080

CMD ["./timeline-backend"]