# PQC Scanner MCP Server Dockerfile
# Multi-stage build for minimal final image

# Build stage
FROM rust:1.75-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml ./

# Create dummy source for dependency caching
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    echo "pub mod patterns; pub mod scanner; pub mod mcp;" > src/lib.rs && \
    mkdir -p src/mcp && \
    echo "pub mod handlers; pub mod protocol;" > src/mcp/mod.rs && \
    touch src/patterns.rs src/scanner.rs src/mcp/handlers.rs src/mcp/protocol.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release || true

# Copy actual source code
COPY src ./src

# Touch to invalidate cache for source files
RUN touch src/main.rs

# Build the actual application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/pqc-scanner /app/pqc-scanner

# Create non-root user
RUN useradd -r -s /bin/false pqc-scanner && \
    chown -R pqc-scanner:pqc-scanner /app

USER pqc-scanner

# Expose port
EXPOSE 8001

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

# Run the server
ENV RUST_LOG=info
CMD ["/app/pqc-scanner"]
