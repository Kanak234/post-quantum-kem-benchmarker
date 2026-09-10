# Build stage
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    clang \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY CMakeLists.txt ./
COPY include/ ./include/
COPY src/ ./src/
COPY tests/ ./tests/
COPY benchmarks/ ./benchmarks/

RUN cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=clang++ && \
    cmake --build build -j$(nproc) && \
    ctest --test-dir build --output-on-failure

# Final runtime stage
FROM debian:bookworm-slim AS runtime

RUN useradd -m -u 1000 -U appuser

WORKDIR /app

COPY --from=builder /src/build/kem_benchmarker /usr/local/bin/kem_benchmarker
COPY --from=builder /src/build/benchmark_kem /usr/local/bin/benchmark_kem

USER appuser

ENTRYPOINT ["/usr/local/bin/kem_benchmarker"]
CMD ["demo", "768"]
