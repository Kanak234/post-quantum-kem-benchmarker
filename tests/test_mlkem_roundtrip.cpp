#include <cassert>
#include <iostream>

#include "kem/ml_kem.hpp"

template <typename KemType>
void test_kem_variant(const std::string& name, size_t iterations) {
  std::cout << "  - Testing " << name << " (" << iterations << " iterations)..." << std::endl;

  for (size_t iter = 0; iter < iterations; ++iter) {
    alignas(64) std::array<uint8_t, KemType::PublicKeyBytes> pk{};
    alignas(64) std::array<uint8_t, KemType::SecretKeyBytes> sk{};
    alignas(64) std::array<uint8_t, KemType::CiphertextBytes> ct{};
    alignas(64) std::array<uint8_t, KemType::SharedSecretBytes> ss_enc{};
    alignas(64) std::array<uint8_t, KemType::SharedSecretBytes> ss_dec{};

    // 1. Key Generation
    KemType::keygen(pk, sk);

    // 2. Encapsulation
    KemType::encaps(ct, ss_enc, pk);

    // 3. Decapsulation
    KemType::decaps(ss_dec, ct, sk);

    // 4. Verification: Shared secret agreement
    assert(ss_enc == ss_dec);

    // 5. Chosen Ciphertext Attack / Tamper Rejection Test
    std::array<uint8_t, KemType::CiphertextBytes> tampered_ct = ct;
    tampered_ct[iter % KemType::CiphertextBytes] ^= 0x5A;  // Flip bits

    std::array<uint8_t, KemType::SharedSecretBytes> ss_tampered{};
    KemType::decaps(ss_tampered, tampered_ct, sk);

    // Implicit rejection: ss_tampered must NOT equal ss_enc
    assert(ss_tampered != ss_enc);
  }

  std::cout << "    * " << name << " Roundtrip & Implicit Rejection: PASSED" << std::endl;
}

int main() {
  std::cout << "[TEST] Running NIST FIPS 203 ML-KEM Complete Verification Suite..." << std::endl;

  test_kem_variant<kem::MlKem512>("ML-KEM-512 (NIST Category 1)", 10);
  test_kem_variant<kem::MlKem768>("ML-KEM-768 (NIST Category 3)", 10);
  test_kem_variant<kem::MlKem1024>("ML-KEM-1024 (NIST Category 5)", 10);

  // Test deterministic KAT repeatability
  {
    std::cout << "  - Testing Deterministic Seed Invariance (KAT)..." << std::endl;
    std::array<uint8_t, 32> d{};
    std::array<uint8_t, 32> z{};
    std::array<uint8_t, 32> m{};
    d.fill(0x42);
    z.fill(0x37);
    m.fill(0x19);

    std::array<uint8_t, kem::MlKem768::PublicKeyBytes> pk1{}, pk2{};
    std::array<uint8_t, kem::MlKem768::SecretKeyBytes> sk1{}, sk2{};
    std::array<uint8_t, kem::MlKem768::CiphertextBytes> ct1{}, ct2{};
    std::array<uint8_t, kem::MlKem768::SharedSecretBytes> ss1{}, ss2{};

    kem::MlKem768::keygen_internal(pk1, sk1, d, z);
    kem::MlKem768::keygen_internal(pk2, sk2, d, z);
    assert(pk1 == pk2);
    assert(sk1 == sk2);

    kem::MlKem768::encaps_internal(ct1, ss1, pk1, m);
    kem::MlKem768::encaps_internal(ct2, ss2, pk2, m);
    assert(ct1 == ct2);
    assert(ss1 == ss2);

    std::array<uint8_t, kem::MlKem768::SharedSecretBytes> ss_dec{};
    kem::MlKem768::decaps(ss_dec, ct1, sk1);
    assert(ss_dec == ss1);
    std::cout << "    * Deterministic KAT Invariance: PASSED" << std::endl;
  }

  std::cout << "[TEST] All ML-KEM verification tests passed successfully!" << std::endl;
  return 0;
}
