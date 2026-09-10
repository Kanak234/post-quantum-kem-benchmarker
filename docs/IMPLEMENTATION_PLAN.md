# Implementation Plan — `post-quantum-kem-benchmarker`

## Tasks & Milestones

- [x] **Phase 1: Project Setup & Build System**
  - [x] Configure `CMakeLists.txt` with C++20, strict warnings (`-Wall -Wextra -Werror -pedantic`), optimization, and test targets.
  - [x] Configure `.gitignore`, `LICENSE` (MIT), `.dockerignore`.

- [x] **Phase 2: Finite Field & Symmetric Foundations**
  - [x] Implement `include/kem/params.hpp` and `include/kem/reduce.hpp` with Montgomery and Barrett reductions.
  - [x] Implement `include/kem/fips202.hpp` and `src/fips202.cpp` with Keccak-f[1600], SHA3-256/512, and SHAKE-128/256.
  - [x] Implement unit test for FIPS 202 symmetric primitives.

- [x] **Phase 3: Number Theoretic Transform (NTT) & Polynomial Ring**
  - [x] Implement `include/kem/ntt.hpp` and `src/ntt.cpp` with twiddle factor tables and Cooley-Tukey / Gentleman-Sande butterflies.
  - [x] Implement `include/kem/poly.hpp` and `src/poly.cpp` with polynomial arithmetic, `compress`/`decompress`, and `ByteEncode`/`ByteDecode`.
  - [x] Implement `include/kem/cbd.hpp` and `src/cbd.cpp` with centered binomial distribution sampling ($\eta \in \{2, 3\}$).
  - [x] Implement unit tests for NTT invertibility and polynomial arithmetic.

- [x] **Phase 4: K-PKE & ML-KEM Key Encapsulation Engine**
  - [x] Implement `include/kem/polyvec.hpp` and `src/polyvec.cpp` with polynomial vectors and matrix operations.
  - [x] Implement `include/kem/indcpa.hpp` and `src/indcpa.cpp` with K-PKE encryption/decryption.
  - [x] Implement `include/kem/ml_kem.hpp` with full ML-KEM-512, ML-KEM-768, and ML-KEM-1024 KeyGen, Encaps, and Decaps with Fujisaki-Okamoto implicit rejection.
  - [x] Implement unit tests for complete KEM roundtrips and tampered ciphertext rejection.

- [x] **Phase 5: Benchmarking Harness & CLI**
  - [x] Implement `benchmarks/benchmark_kem.cpp` measuring operations/sec and microsecond latency across NTT, Keccak, and KEM operations.
  - [x] Implement `src/main.cpp` with CLI modes for demonstration, key exchange simulation, and JSON metrics reporting.
  - [x] Build and verify multi-stage `Dockerfile` and `.github/workflows/ci.yml`.

- [x] **Phase 6: Documentation, Release & Publishing**
  - [x] Write `docs/EXPLAIN.md` covering all 6 mandatory sections.
  - [x] Write `README.md` with educational warning, architecture flowchart, and measured benchmark numbers.
  - [x] Write `CHANGELOG.md`.
  - [x] Create conventional commits, tag `v1.0.0`, publish to GitHub, and update master portfolio tracking docs.
