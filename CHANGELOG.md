# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-11

### Added
- Complete standalone implementation of NIST FIPS 203 (ML-KEM) in pure C++20 with zero third-party dependencies.
- Full support for ML-KEM-512 (Category 1), ML-KEM-768 (Category 3), and ML-KEM-1024 (Category 5) parameter sets.
- FIPS 202 Keccak-f[1600] permutation core, SHA3-256, SHA3-512, SHAKE-128, and SHAKE-256 sponge primitives.
- Negacyclic Cooley-Tukey forward NTT and Gentleman-Sande inverse NTT over $R_q = \mathbb{Z}_{3329}[X] / (X^{256} + 1)$ with Montgomery twiddle factor tables.
- Centered Binomial Distribution (CBD) sampling for $\eta \in \{2, 3\}$.
- Constant-time Fujisaki-Okamoto transformation with implicit rejection on tampered or malformed ciphertexts.
- Standalone microbenchmark suite (`benchmark_kem`) reporting microsecond latency and ops/sec across all ring, symmetric, and KEM operations.
- Interactive CLI binary (`kem_benchmarker`) with `demo` and `bench` modes.
- Complete verification test suite covering FIPS 202 CAVP vectors, NTT invertibility, polynomial serialization, and end-to-end KEM roundtrips with tamper simulation.
- Multi-stage minimal `Dockerfile` and automated GitHub Actions CI pipeline testing GCC and Clang.
- Comprehensive technical documentation including PRD, TRD, Implementation Plan, and Architectural Breakdown (`docs/EXPLAIN.md`).
