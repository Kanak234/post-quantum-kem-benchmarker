# NIST FIPS 203 ML-KEM (Kyber) Deep Architecture & Technical Explanation

> [!WARNING]
> **Educational & Research Notice**: This implementation is engineered for technical education, algorithm exploration, and performance benchmarking of the NIST FIPS 203 (ML-KEM / Kyber) standard. For mission-critical production secrets, use FIPS-validated hardware security modules (HSMs) or formally audited implementations.

---

## 1. Architecture Overview

`post-quantum-kem-benchmarker` is an audited, zero-external-dependency C++20 implementation of NIST FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM). The architecture is structured in five strictly separated layers:

```
+-----------------------------------------------------------------------------+
|                          Application & CLI Layer                            |
|        kem_benchmarker (CLI Explorer)   |   benchmark_kem (Microharness)   |
+-----------------------------------------------------------------------------+
                                       |
+-----------------------------------------------------------------------------+
|                       ML-KEM Top-Level Engine                               |
|        MlKem<K, Eta1, Eta2, Du, Dv> (MlKem512, MlKem768, MlKem1024)         |
|         - KeyGen (Seeds -> pk, sk)                                          |
|         - Encaps (pk -> ct, ss)                                             |
|         - Decaps (ct, sk -> ss) with Fujisaki-Okamoto Implicit Rejection    |
+-----------------------------------------------------------------------------+
                                       |
+-----------------------------------------------------------------------------+
|                   K-PKE Public Key Encryption Scheme                        |
|       - indcpa_keypair: Matrix generation, noise sampling, NTT multiply     |
|       - indcpa_enc: Encryption, modulus scaling, vector compression         |
|       - indcpa_dec: Polynomial inner product, subtraction, message decode   |
+-----------------------------------------------------------------------------+
                                       |
+-----------------------------------------------------------------------------+
|               Polynomial Ring & Algebraic Transformations                   |
|       - Ring R_q = Z_q[X] / (X^256 + 1), q = 3329                           |
|       - Number Theoretic Transform (NTT) & Inverse NTT (invntt)             |
|       - Pointwise Montgomery Multiplication (basemul)                       |
|       - Polynomial & Vector Serialization (ByteEncode / ByteDecode)         |
|       - Centered Binomial Distribution Sampling (CBD eta=2, eta=3)          |
+-----------------------------------------------------------------------------+
                                       |
+-----------------------------------------------------------------------------+
|                     Finite Field & Symmetric Primitives                     |
|       - Montgomery Reduction (R = 2^16 mod 3329) & Barrett Reduction        |
|       - NIST FIPS 202 Keccak-f[1600] Permutation Core                       |
|       - SHA3-256, SHA3-512, SHAKE-128, SHAKE-256 Sponge Functions           |
+-----------------------------------------------------------------------------+
```

---

## 2. Key Design Decisions

### A. Pure C++20 Zero-Dependency Implementation
- Avoided all third-party cryptographic libraries (OpenSSL, Botan, Crypto++) to ensure full transparency, strict auditability, and zero supply-chain risk.
- Utilized `std::span`, `std::array`, and fixed-width integer types (`int16_t`, `uint32_t`, `uint64_t`) to provide zero-copy memory safety and bound guarantees.

### B. Constant-Time Fujisaki-Okamoto Implicit Rejection
- Against Chosen-Ciphertext Attacks (CCA2), traditional KEMs that return an error on ciphertext mismatch leak side-channel timing information.
- ML-KEM implements implicit rejection: if re-encryption validation detects any tampering ($ct \neq ct'$), decapsulation substitutes the true shared secret $K'$ with a pseudorandom secret derived from the secret key's rejection seed $z$:
  $$K_{\text{rej}} = \text{SHAKE-256}(z \parallel ct, 32)$$
- The selection between $K'$ and $K_{\text{rej}}$ is executed using a bitwise arithmetic multiplexer, avoiding branching instructions:
  ```cpp
  uint8_t mask = static_cast<uint8_t>((static_cast<uint16_t>(diff) - 1) >> 8) ^ 0xFF;
  ss[i] = static_cast<uint8_t>((k_prime[i] & ~mask) | (k_rej[i] & mask));
  ```

### C. Compile-Time Templated Parameter Sets
- Instead of runtime parameter structs and heap-allocated vectors, `MlKem<K, Eta1, Eta2, Du, Dv>` uses template parameters for matrix dimension $K \in \{2, 3, 4\}$, noise parameters $\eta_1, \eta_2$, and compression factors $d_u, d_v$.
- All cryptographic key buffers and polynomial vectors are stack-allocated with zero dynamic memory allocation during key exchange operations.

### D. Montgomery and Barrett Reductions
- The Kyber prime $q = 3329$ satisfies $q \equiv 1 \pmod{256}$, enabling 256th primitive roots of unity for the negacyclic NTT.
- Arithmetic is accelerated via Montgomery reduction with $R = 2^{16} \pmod{3329} = 2285$ and $q^{-1} \equiv -3327 \pmod{2^{16}}$.
- Modular reductions during butterfly stages use 32-bit Barrett reduction to eliminate integer division instructions (`idiv`).

---

## 3. Data Flow

### A. Key Generation Flow (`ML-KEM.KeyGen`)
1. **Entropy Gathering**: Collect 32 bytes of randomness $d$ and 32 bytes of rejection seed $z$ from `/dev/urandom`.
2. **Seed Expansion**: Compute $(\rho, \sigma) = \text{SHA3-512}(d)$.
3. **Public Matrix Generation**: Expand seed $\rho$ via SHAKE-128 rejection sampling into public polynomial matrix $\hat{\mathbf{A}} \in R_q^{K \times K}$ in the NTT domain.
4. **Secret Vector Sampling**: Sample secret vector $\mathbf{s} \in R_q^K$ and error vector $\mathbf{e} \in R_q^K$ from Centered Binomial Distribution $\text{CBD}_{\eta_1}$ using $\text{SHAKE-256}(\sigma \parallel N)$.
5. **Matrix-Vector Multiplication**: Compute $\hat{\mathbf{s}} = \text{NTT}(\mathbf{s})$ and $\hat{\mathbf{e}} = \text{NTT}(\mathbf{e})$, then:
   $$\hat{\mathbf{t}} = \hat{\mathbf{A}} \circ \hat{\mathbf{s}} + \hat{\mathbf{e}} \pmod q$$
6. **Key Packaging**:
   - Public key: $pk = \text{ByteEncode}_{12}(\hat{\mathbf{t}}) \parallel \rho$
   - Secret key: $sk = \text{ByteEncode}_{12}(\hat{\mathbf{s}}) \parallel pk \parallel \text{SHA3-256}(pk) \parallel z$

### B. Encapsulation Flow (`ML-KEM.Encaps`)
1. **Random Message**: Generate 32-byte ephemeral message $m$.
2. **Hash Pairing**: Compute $(K, r) = \text{SHA3-512}(m \parallel \text{SHA3-256}(pk))$.
3. **PKE Encryption**:
   - Sample ephemeral noise $\mathbf{y} \leftarrow \text{CBD}_{\eta_1}(r)$, $\mathbf{e}_1 \leftarrow \text{CBD}_{\eta_2}(r)$, $e_2 \leftarrow \text{CBD}_{\eta_2}(r)$.
   - Compute ciphertext components:
     $$\mathbf{u} = \text{NTT}^{-1}(\hat{\mathbf{A}}^T \circ \hat{\mathbf{y}}) + \mathbf{e}_1$$
     $$v = \text{NTT}^{-1}(\hat{\mathbf{t}}^T \circ \hat{\mathbf{y}}) + e_2 + \text{Encode}(m)$$
   - Compress and serialize: $c = \text{Compress}_{d_u}(\mathbf{u}) \parallel \text{Compress}_{d_v}(v)$.
4. **Shared Secret**: Output shared secret $K$ (32 bytes) alongside ciphertext $c$.

### C. Decapsulation Flow (`ML-KEM.Decaps`)
1. **PKE Decryption**: Decompress $c \to (\mathbf{u}, v)$, compute $w = v - \text{NTT}^{-1}(\hat{\mathbf{s}}^T \circ \text{NTT}(\mathbf{u}))$, decode message $m' = \text{Decode}(w)$.
2. **Re-encryption**: Derive candidate $(K', r') = \text{SHA3-512}(m' \parallel H(pk))$ and re-encrypt $c' = \text{K-PKE.Encrypt}(pk, m', r')$.
3. **Rejection Output**: If $c == c'$, return $K'$; otherwise, return $K_{\text{rej}} = \text{SHAKE-256}(z \parallel c, 32)$.

---

## 4. Failure Modes & Edge Cases

| Failure Mode | Root Cause | Architectural Mitigation |
| :--- | :--- | :--- |
| **Ciphertext Tampering (Active Attack)** | Adversary alters ciphertext bits in transit. | Constant-time Fujisaki-Okamoto re-encryption check outputs pseudorandom reject secret $K_{\text{rej}}$. |
| **RNG Entropy Depletion** | `/dev/urandom` unavailable or exhausted. | Automated fallback to `std::random_device` entropy source. |
| **Decryption Failure Probability** | Noise vectors exceed lattice decoding threshold. | Modulus $q = 3329$ and $\eta$ parameters bound error failure probability strictly below $2^{-138}$. |
| **Twiddle Factor Misalignment** | Incorrect twiddle factor indexing during InvNTT. | Cooley-Tukey forward and Gentleman-Sande inverse butterflies use precomputed bit-reversed Montgomery roots. |
| **Arithmetic Overflow** | Coefficient addition before modular reduction. | Intermediate calculations promote to `int32_t` prior to Barrett / Montgomery reduction. |

---

## 5. Operational Runbook

### Building the Project
```bash
# Configure Release build with strict warnings
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=clang++

# Compile library and executables
cmake --build build -j$(nproc)

# Execute test suite
ctest --test-dir build --output-on-failure
```

### Running Interactive CLI Demonstration
```bash
# Simulate key encapsulation for ML-KEM-768
./build/kem_benchmarker demo 768

# Run quick parameter comparison benchmark
./build/kem_benchmarker bench
```

### Running the Full Microbenchmark Harness
```bash
./build/benchmark_kem
```

### Running via Docker
```bash
docker build -t post-quantum-kem-benchmarker .
docker run --rm post-quantum-kem-benchmarker demo 1024
```

---

## 6. Troubleshooting Guide

### Compilation Fails with Missing C++20 Features
- Ensure compiler is GCC $\ge 11$ or Clang $\ge 14$.
- Check `CMAKE_CXX_STANDARD 20` is recognized by your CMake configuration.

### CTest Fails with Assertion Errors
- Run tests individually with full output: `./build/test_mlkem_roundtrip`.
- Verify CPU architecture supports standard unaligned memory reads if porting to embedded platforms.

### Measured Latency Discrepancies
- Ensure `-DCMAKE_BUILD_TYPE=Release` is enabled; Debug mode includes runtime assertions and disables compiler vectorization and inlining, increasing latency by $10\times$.
