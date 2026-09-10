# Technical Requirements Document (TRD) — `post-quantum-kem-benchmarker`

> [!WARNING]
> Educational implementation only. Not audited for side-channel security. Do NOT use in production.

---

## 1. Technical Architecture

The engine is structured into modular layers from raw finite field arithmetic up to the Fujisaki-Okamoto transformation:

```text
┌──────────────────────────────────────────────────────────┐
│                     Benchmarking CLI                     │
│       (Operation Timers, Cycle Counts, Throughput)       │
└────────────────────────────┬─────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────┐
│              ML-KEM Protocol Layer (FIPS 203)            │
│   - MlKem512 (k=2)  - MlKem768 (k=3)  - MlKem1024 (k=4)  │
│   - KeyGen()        - Encaps()        - Decaps()         │
└────────────────────────────┬─────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────┐
│              K-PKE Public-Key Encryption Engine          │
│   - Matrix Generation (SHAKE-128 SampleNTT)              │
│   - Noise Sampling (Centered Binomial CBD_eta)           │
│   - Compression & Byte Serialization (d_u, d_v)          │
└────────────────────────────┬─────────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                             ▼
┌───────────────────────────┐ ┌────────────────────────────┐
│   Polynomial Ring R_q     │ │    Symmetric Cryptography  │
│ - Degree n = 256, q = 3329│ │ - Keccak-f[1600]           │
│ - Forward NTT & InvNTT    │ │ - SHA3-256 / SHA3-512      │
│ - Montgomery Reduction    │ │ - SHAKE-128 / SHAKE-256    │
│ - Barrett Reduction       │ │ - Sponge Function          │
└───────────────────────────┘ └────────────────────────────┘
```

---

## 2. Technology Stack & Build Tools

- **Language:** C++20 standard (`std::span`, `std::array`, `concepts`, structured bindings).
- **Build System:** CMake $\ge 3.20$ with Ninja or Make.
- **Compiler Support:** Clang 16+ or GCC 11+ on Linux x86_64.
- **Compiler Flags:** `-Wall -Wextra -Werror -pedantic -Wconversion -Wsign-conversion -O3`.
- **Dependencies:** Standard C++ library (`<cstdint>`, `<array>`, `<span>`, `<chrono>`). Zero third-party dependencies.

---

## 3. Mathematical Foundations

### 3.1 Finite Field $\mathbb{Z}_q$ ($q = 3329$)
- $q = 3329$ is a prime with $q \equiv 1 \pmod{256}$, specifically $3329 = 13 \times 256 + 1$.
- This enables a full splitting of $X^{256} + 1$ into 256 linear factors over $\mathbb{Z}_q$ using the primitive 256th root of unity $\zeta = 17$.
- **Montgomery Reduction:**
  For modulus $q = 3329$ and radix $R = 2^{16} = 65536$:
  $$R^{-1} \equiv 169 \pmod q, \quad q' = -q^{-1} \equiv 3327 \equiv -62209 \pmod R$$
- **Barrett Reduction:**
  Reduces an integer $a \in [-2^{15}, 2^{15}]$ to $[0, q)$:
  $$v = (a \cdot 20159 + 2^{25}) \gg 26; \quad a - v \cdot 3329$$

### 3.2 Number Theoretic Transform (NTT)
- Fast polynomial multiplication in $R_q = \mathbb{Z}_q[X]/(X^{256} + 1)$ in $O(n \log n)$ time.
- Operates on 128 quadratic polynomials:
  $$\hat{a} = \text{NTT}(a) \implies \hat{a}_{2i} + \hat{a}_{2i+1} X$$
- Pointwise multiplication multiplies pairs of linear polynomials modulo $X^2 - \zeta^{2 \cdot \text{bitrev}(i) + 1}$.

### 3.3 Symmetric Functions
- **Keccak-f[1600]:** 24 rounds of permutations over 1600-bit state ($5 \times 5 \times 64$ bits): $\theta, \rho, \pi, \chi, \iota$.
- **SHAKE-128:** Rate $r = 1344$ bits (168 bytes), capacity $c = 256$ bits. Used for public matrix generation $\mathbf{A} \in R_q^{k \times k}$.
- **SHAKE-256:** Rate $r = 1088$ bits (136 bytes), capacity $c = 512$ bits. Used for noise sampling and pseudo-random generation.
- **SHA3-256 & SHA3-512:** Used for hashing seeds and Fujisaki-Okamoto derivation.

---

## 4. Source Layout & Design

```text
include/kem/
├── params.hpp         # Constants (q, n, zeta) and parameter set structs
├── reduce.hpp         # Montgomery and Barrett reduction primitives
├── ntt.hpp            # Forward NTT, Inverse NTT, and twiddle tables
├── poly.hpp           # Polynomial structure (256 int16_t coefficients)
├── polyvec.hpp        # Vector of k polynomials
├── fips202.hpp        # Keccak-f[1600], SHA-3, and SHAKE-128/256
├── cbd.hpp            # Centered Binomial Distribution sampling
├── indcpa.hpp         # K-PKE encryption and decryption (Algorithms 12-14)
└── ml_kem.hpp         # ML-KEM KeyGen, Encaps, Decaps (Algorithms 15-17)

src/
├── reduce.cpp         # Field reduction implementation
├── ntt.cpp            # NTT butterflies and tables
├── poly.cpp           # Polynomial ring arithmetic and compression
├── polyvec.cpp        # Matrix-vector polynomial operations
├── fips202.cpp        # Keccak permutation and sponge
├── cbd.cpp            # CBD noise sampler
├── indcpa.cpp         # K-PKE primitives
└── main.cpp           # Interactive CLI & benchmark runner

benchmarks/
└── benchmark_kem.cpp  # Microbenchmark suite measuring cycles and microseconds
```
