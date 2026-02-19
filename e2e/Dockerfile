# Halt Linux test image
#
# Builds halt from source on Ubuntu 24.04 (kernel 6.8, Landlock ABI ≥ v4)
# and provides all tools needed for the agent-config test suite.
#
# Build:
#   docker build -t halt-test -f docker/Dockerfile .
#
# Run unit + integration tests:
#   docker run --rm --cap-add NET_ADMIN halt-test cargo test --workspace
#
# Run agent-config smoke tests:
#   docker run --rm --cap-add NET_ADMIN halt-test /halt/docker/test-agent-configs.sh
#
# NET_ADMIN is required for halt's Linux network-namespace isolation
# (ProxyOnly / LocalhostOnly modes call unshare(CLONE_NEWNET) + ip-link).

# ── Stage 1: build ───────────────────────────────────────────────────────────
FROM rust:1.85-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /halt
COPY . .

RUN cargo build --workspace --release

# ── Stage 2: test runtime ────────────────────────────────────────────────────
FROM ubuntu:24.04

# iproute2  — ip-link / ip-netns commands used by halt's ProxyOnly mode
# curl      — network tests (proxy-aware HTTP client)
# bash      — test script and SOCKS5 /dev/tcp tests
# ca-certificates — TLS roots for HTTPS in curl tests
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    curl \
    bash \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled halt binary.
COPY --from=builder /halt/target/release/halt /usr/local/bin/halt

# Copy configs and test script so they are available inside the container.
COPY configs/ /halt/configs/
COPY docker/test-agent-configs.sh /halt/docker/test-agent-configs.sh
RUN chmod +x /halt/docker/test-agent-configs.sh

WORKDIR /workspace

# Default: run the agent-config smoke tests.
CMD ["/halt/docker/test-agent-configs.sh"]
