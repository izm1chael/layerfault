# syntax=docker/dockerfile:1.7
FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim
RUN useradd --system --uid 65532 --create-home layerfault \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates bubblewrap \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/layerfault /usr/local/bin/layerfault
USER 65532:65532
WORKDIR /var/lib/layerfault
ENTRYPOINT ["/usr/local/bin/layerfault"]
