FROM rust:1.89.0-trixie AS builder

# Install CA certificates in the builder stage
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY static ./static

# Configure git to use system certificates and build
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
RUN update-ca-certificates && cargo build --release

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/timeline-backend /app/timeline-backend
COPY --from=builder /app/static ./static

# Default ports (can be customized via HTTP_PORT and HTTPS_PORT environment variables)
EXPOSE 8080
EXPOSE 8443

CMD ["./timeline-backend"]
