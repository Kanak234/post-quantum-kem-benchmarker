#pragma once

#include <cstddef>
#include <cstdint>

namespace kem {

constexpr size_t KYBER_N = 256;
constexpr int16_t KYBER_Q = 3329;
constexpr size_t KYBER_SYMBYTES =
    32; // Size of hashes, seeds, and shared secret

// Montgomery and Barrett reduction constants
constexpr int16_t MONTGOMERY_R = 2285; // 2^16 mod q
constexpr int16_t QINV = -3327;        // -q^-1 mod 2^16

struct KemParams {
  size_t k;                  // Matrix dimension
  size_t eta1;               // Noise parameter 1
  size_t eta2;               // Noise parameter 2
  size_t du;                 // Vector compression parameter
  size_t dv;                 // Scalar compression parameter
  size_t poly_bytes;         // 384
  size_t polyvec_bytes;      // 384 * k
  size_t polyvec_compressed; // 32 * du * k
  size_t poly_compressed;    // 32 * dv
  size_t public_key_bytes;   // polyvec_bytes + 32
  size_t secret_key_bytes;   // polyvec_bytes + public_key_bytes + 32 + 32
  size_t ciphertext_bytes;   // polyvec_compressed + poly_compressed
};

constexpr KemParams PARAMS_512 = {.k = 2,
                                  .eta1 = 3,
                                  .eta2 = 2,
                                  .du = 10,
                                  .dv = 4,
                                  .poly_bytes = 384,
                                  .polyvec_bytes = 768,
                                  .polyvec_compressed = 640,
                                  .poly_compressed = 128,
                                  .public_key_bytes = 800,
                                  .secret_key_bytes = 1632,
                                  .ciphertext_bytes = 768};

constexpr KemParams PARAMS_768 = {.k = 3,
                                  .eta1 = 2,
                                  .eta2 = 2,
                                  .du = 10,
                                  .dv = 4,
                                  .poly_bytes = 384,
                                  .polyvec_bytes = 1152,
                                  .polyvec_compressed = 960,
                                  .poly_compressed = 128,
                                  .public_key_bytes = 1184,
                                  .secret_key_bytes = 2400,
                                  .ciphertext_bytes = 1088};

constexpr KemParams PARAMS_1024 = {.k = 4,
                                   .eta1 = 2,
                                   .eta2 = 2,
                                   .du = 11,
                                   .dv = 5,
                                   .poly_bytes = 384,
                                   .polyvec_bytes = 1536,
                                   .polyvec_compressed = 1408,
                                   .poly_compressed = 160,
                                   .public_key_bytes = 1568,
                                   .secret_key_bytes = 3168,
                                   .ciphertext_bytes = 1568};

} // namespace kem
