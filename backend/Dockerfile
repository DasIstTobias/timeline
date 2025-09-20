FROM rust:1.89.0-trixie AS builder

# Install CA certificates in the builder stage
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY static ./static

RUN cargo build --release

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/timeline-backend /app/timeline-backend
COPY --from=builder /app/static ./static

EXPOSE 8080

CMD ["./timeline-backend"]
