# syntax=docker/dockerfile:1.7

FROM rust:1-bookworm AS builder

WORKDIR /src
ENV CARGO_HTTP_MULTIPLEXING=false \
    CARGO_HTTP_TIMEOUT=600 \
    CARGO_NET_RETRY=20
RUN printf 'precedence ::ffff:0:0/96 100\n' >> /etc/gai.conf
COPY .cargo ./.cargo
ARG CARGO_CONFIG=.cargo/config.toml
RUN if [ "$CARGO_CONFIG" != ".cargo/config.toml" ]; then cp "$CARGO_CONFIG" .cargo/config.toml; fi
COPY Cargo.toml ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo generate-lockfile \
    && cargo build --release --locked

FROM debian:bookworm-slim

ENV TZ=Asia/Shanghai
COPY --from=builder /src/target/release/rustacme /usr/local/bin/rustacme

VOLUME ["/certs"]
ENTRYPOINT ["rustacme"]
