ARG BUILDER_IMAGE=rust:1-bookworm
ARG RUNTIME_IMAGE=debian:bookworm-slim

FROM ${BUILDER_IMAGE} AS builder

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
RUN cargo generate-lockfile \
    && cargo build --release --locked

FROM ${RUNTIME_IMAGE}

ENV TZ=Asia/Shanghai
COPY --from=builder /src/target/release/rustacme /usr/local/bin/rustacme

VOLUME ["/certs"]
ENTRYPOINT ["rustacme"]
