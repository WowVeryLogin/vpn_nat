FROM rust:1.91-bookworm AS builder
WORKDIR /app

# copy your source
COPY . .

# build in release mode
RUN cargo build --release

FROM debian:bookworm-slim

COPY --from=builder /app/target/release/server /usr/local/bin/server

ENTRYPOINT ["/usr/local/bin/server"]
