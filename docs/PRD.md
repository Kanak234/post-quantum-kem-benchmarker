# Product Requirements Document (PRD) — `post-quantum-kem-benchmarker`

> [!WARNING]
> **Educational & Research Implementation Only**
> This software is strictly intended for educational, academic research, and performance benchmarking exploration. It has not undergone formal third-party cryptographic security reviews or side-channel leakage certifications. **UNDER NO CIRCUMSTANCES should this implementation be deployed in production security systems.**

---

## 1. Product Overview
`post-quantum-kem-benchmarker` is an independent, pure C++20 reference implementation and comparative benchmarking suite for the NIST Post-Quantum Cryptography (PQC) standard **ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)**, as specified in **NIST FIPS 203** (formerly known as CRYSTALS-Kyber).

It implements complete polynomial ring arithmetic over $R_q = \mathbb{Z}_q[X]/(X^{256} + 1)$, Number Theoretic Transforms (NTT), centered binomial distribution sampling, and Keccak symmetric permutations (SHA3-256, SHA3-512, SHAKE-128, SHAKE-256) with zero external library dependencies.

---

## 2. Problem Statement & Motivation
Shor's algorithm running on a sufficiently powerful cryptographically relevant quantum computer (CRQC) will break conventional public key cryptosystems (RSA, Diffie-Hellman, ECDH). In August 2024, NIST released FIPS 203 standardizing ML-KEM as the primary quantum-resistant key establishment protocol.

However, understanding and benchmarking ML-KEM is hindered by:
1. **Opaque Optimized Assembly:** Production reference codes frequently intertwine AVX2/AVX-512 assembly with complex pointer arithmetic, obscuring the mathematical mechanics for security researchers.
2. **Missing Granular Microbenchmarks:** Existing tools report end-to-end handshake timings, lacking micro-benchmarks that break down latency across Number Theoretic Transforms, rejection sampling, Keccak absorption, and polynomial vector matrix multiplications.
3. **Lack of Pure Modern C++ Implementations:** Most available open-source implementations are written in C89/C99 or rely on third-party crypto frameworks like OpenSSL 3.x.

`post-quantum-kem-benchmarker` provides clean, highly readable, standard C++20 code accompanied by fine-grained microbenchmarks for all three NIST security parameter sets: ML-KEM-512, ML-KEM-768, and ML-KEM-1024.

---

## 3. Goals & Non-Goals

### Goals
- **Strict NIST FIPS 203 Conformance:** Implement the exact mathematical algorithms specified in FIPS 203:
  - Algorithm 12: `K-PKE.KeyGen`
  - Algorithm 13: `K-PKE.Encrypt`
  - Algorithm 14: `K-PKE.Decrypt`
  - Algorithm 15: `ML-KEM.KeyGen`
  - Algorithm 16: `ML-KEM.Encaps`
  - Algorithm 17: `ML-KEM.Decaps`
- **All Three NIST Parameter Sets:**
  - `ML-KEM-512` (Category 1, equivalent to AES-128)
  - `ML-KEM-768` (Category 3, equivalent to AES-192, default recommended)
  - `ML-KEM-1024` (Category 5, equivalent to AES-256)
- **Zero Third-Party Dependencies:** Pure C++20 standard library only; includes internal Keccak-f[1600] and SHAKE engines.
- **Detailed Microbenchmarking:** High-resolution timing (clock cycles and microseconds) measuring:
  - NTT forward transform and inverse NTT
  - Keccak SHAKE-128 / SHAKE-256 throughput
  - Polynomial ring multiplication and centered binomial sampling
  - `KeyGen`, `Encaps`, `Decaps` operations/sec across all parameter sets.
- **Verification Against Known Vectors:** Unit tests verifying encapsulation/decapsulation roundtrips ($ss_{\text{encaps}} == ss_{\text{decaps}}$) and implicit rejection on modified ciphertexts.

### Non-Goals
- Production deployment or side-channel hardened constant-time guarantees across all CPU architectures.
- Digital signature schemes (ML-DSA / SPHINCS+); KEM only.

---

## 4. Parameter Sets & Specifications

| Parameter | Notation | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
| :--- | :---: | :---: | :---: | :---: |
| **NIST Security Level** | Category | 1 (AES-128) | 3 (AES-192) | 5 (AES-256) |
| **Modulus ($q$)** | $q$ | 3329 | 3329 | 3329 |
| **Ring Degree ($n$)** | $n$ | 256 | 256 | 256 |
| **Matrix Dimension ($k$)** | $k$ | 2 | 3 | 4 |
| **Noise Parameter ($\eta_1$)** | $\eta_1$ | 3 | 2 | 2 |
| **Noise Parameter ($\eta_2$)** | $\eta_2$ | 2 | 2 | 2 |
| **Vector Compression ($d_u$)** | $d_u$ | 10 | 10 | 11 |
| **Scalar Compression ($d_v$)** | $d_v$ | 4 | 4 | 5 |
| **Public Key Size** | Bytes | 800 | 1,184 | 1,568 |
| **Private Key Size** | Bytes | 1,632 | 2,400 | 3,168 |
| **Ciphertext Size** | Bytes | 768 | 1,088 | 1,568 |
| **Shared Secret Size** | Bytes | 32 | 32 | 32 |

---

## 5. Acceptance Criteria
1. Clean compilation under `-Wall -Wextra -Werror -pedantic` with Clang and GCC in C++20.
2. 100% pass rate on test suites verifying:
   - Keccak-f[1600], SHA3-256, SHA3-512, SHAKE-128, SHAKE-256 standard test vectors.
   - NTT invertible roundtrip: $\text{invNTT}(\text{NTT}(a)) \equiv a \pmod q$.
   - Pointwise multiplication in NTT domain matching polynomial ring multiplication.
   - ML-KEM-512, ML-KEM-768, ML-KEM-1024 complete key encapsulation and decapsulation roundtrip.
   - Implicit rejection: invalid or modified ciphertext decapsulates to a pseudorandom key, NOT the legitimate shared secret.
3. Standalone benchmark binary outputting operations/second and latency in microseconds for all operations.
4. Complete documentation (`docs/EXPLAIN.md`, `README.md`, `CHANGELOG.md`, `Dockerfile`, CI workflow).
