FROM rust:1.91-bookworm AS builder
WORKDIR /app

# copy your source
COPY . .

# build in release mode
RUN cargo build --release

FROM debian:bookworm-slim

COPY --from=builder /app/target/release/client /usr/local/bin/client
COPY --from=builder /app/client/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --from=builder /app/xchacha20.key /etc/

RUN apt-get update && apt-get install -y iproute2 iptables curl tcpdump && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
