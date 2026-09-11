# Multi-stage Dockerfile for post-quantum-kem-benchmarker
FROM debian:bookworm-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    clang \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN rm -rf build && cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=clang++ && \
    cmake --build build -j$(nproc) && \
    ctest --test-dir build --output-on-failure

# Final runtime stage
FROM debian:bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 10001 -U appuser

WORKDIR /app
COPY --from=builder /src/build/kem_benchmarker /usr/local/bin/kem_benchmarker
COPY --from=builder /src/build/benchmark_kem /usr/local/bin/benchmark_kem

RUN chown -R appuser:appuser /app
USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/kem_benchmarker", "health"] || exit 1

ENTRYPOINT ["/usr/local/bin/kem_benchmarker"]
CMD ["demo", "768"]
