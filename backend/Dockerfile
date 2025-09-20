FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY target/release/timeline-backend /app/timeline-backend
COPY static ./static

EXPOSE 8080

CMD ["./timeline-backend"]