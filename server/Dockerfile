FROM rust:1.91-bookworm AS builder
WORKDIR /app

# copy your source
COPY . .

# build in release mode
RUN cargo build --release

FROM debian:bookworm-slim

COPY --from=builder /app/target/release/server /usr/local/bin/server
COPY --from=builder /app/xchacha20.key /etc/
COPY --from=builder /app/cert.pem /etc/
COPY --from=builder /app/key.pem /etc/

ENTRYPOINT ["/usr/local/bin/server"]
