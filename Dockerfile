# AegisBPF Multi-stage Dockerfile
# Build stage: compile the agent
# Runtime stage: minimal image with just the binary

# =============================================================================
# Build Stage
# =============================================================================
FROM ubuntu:24.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    bpftool \
    libbpf-dev \
    libsystemd-dev \
    pkg-config \
    cmake \
    ninja-build \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy source files
COPY CMakeLists.txt ./
COPY bpf/ ./bpf/
COPY src/ ./src/
COPY config/ ./config/
COPY packaging/ ./packaging/

# Build the agent
RUN cmake -S . -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=OFF \
    && cmake --build build

# =============================================================================
# Runtime Stage
# =============================================================================
FROM ubuntu:24.04 AS runtime

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libbpf1 \
    libsystemd0 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user (will still need capabilities)
RUN useradd -r -s /bin/false aegisbpf

# Create required directories
RUN mkdir -p /var/lib/aegisbpf /etc/aegisbpf \
    && chown aegisbpf:aegisbpf /var/lib/aegisbpf

# Copy binary and BPF object from builder
COPY --from=builder /build/build/aegisbpf /usr/bin/aegisbpf
COPY --from=builder /build/build/aegis.bpf.o /usr/lib/aegisbpf/aegis.bpf.o

# Copy example configuration
COPY --from=builder /build/config/policy.example /etc/aegisbpf/policy.example

# Set capabilities on the binary (requires --cap-add during build or runtime)
# These capabilities are required for BPF operations
# In production, use: docker run --cap-add=SYS_ADMIN --cap-add=BPF --cap-add=PERFMON
# Note: setcap doesn't work in Docker build, capabilities must be granted at runtime

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/bin/aegisbpf", "health"]

# Default command (can be overridden)
ENTRYPOINT ["/usr/bin/aegisbpf"]
CMD ["run", "--audit", "--log=stdout", "--log-format=json"]

# Metadata labels
LABEL org.opencontainers.image.title="AegisBPF"
LABEL org.opencontainers.image.description="eBPF-based runtime security agent"
LABEL org.opencontainers.image.vendor="AegisBPF"
LABEL org.opencontainers.image.source="https://github.com/aegisbpf/aegisbpf"
LABEL org.opencontainers.image.licenses="Apache-2.0"
