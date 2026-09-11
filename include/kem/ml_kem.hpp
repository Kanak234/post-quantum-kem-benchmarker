#pragma once

#include <array>
#include <cstring>
#include <fstream>
#include <random>
#include <span>
#include <string_view>

#include "kem/fips202.hpp"
#include "kem/indcpa.hpp"
#include "kem/params.hpp"

namespace kem {

// CSPRNG random bytes generator
inline void random_bytes(std::span<uint8_t> out) {
  std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
  if (urandom.is_open()) {
    urandom.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
    if (urandom.gcount() == static_cast<std::streamsize>(out.size())) {
      return;
    }
  }
  // Fallback if /dev/urandom cannot be read
  std::random_device rd;
  for (size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>(rd() & 0xFF);
  }
}

template <size_t K, size_t Eta1, size_t Eta2, size_t Du, size_t Dv>
class MlKem {
 public:
  static constexpr size_t Dimension = K;
  static constexpr size_t PublicKeyBytes = 384 * K + 32;
  static constexpr size_t SecretKeyBytes = 384 * K + PublicKeyBytes + 32 + 32;
  static constexpr size_t CiphertextBytes = 32 * Du * K + 32 * Dv;
  static constexpr size_t SharedSecretBytes = 32;

  static constexpr std::string_view name() {
    if constexpr (K == 2) return "ML-KEM-512";
    if constexpr (K == 3) return "ML-KEM-768";
    if constexpr (K == 4) return "ML-KEM-1024";
    return "ML-KEM-Custom";
  }

  // Deterministic KeyGen given seeds d and z (FIPS 203 ML-KEM.KeyGen_internal)
  static void keygen_internal(std::span<uint8_t, PublicKeyBytes> pk,
                              std::span<uint8_t, SecretKeyBytes> sk, std::span<const uint8_t, 32> d,
                              std::span<const uint8_t, 32> z) {
    // 1. K-PKE KeyGen
    indcpa_keypair<K, Eta1>(pk, sk.template subspan<0, 384 * K>(), d);

    // 2. sk[384*K .. 384*K + PublicKeyBytes] = pk
    std::memcpy(sk.data() + 384 * K, pk.data(), PublicKeyBytes);

    // 3. sk[.. + 32] = H(pk)
    std::span<uint8_t, 32> h(sk.data() + 384 * K + PublicKeyBytes, 32);
    sha3_256(pk, h);

    // 4. sk[.. + 32] = z
    std::memcpy(sk.data() + 384 * K + PublicKeyBytes + 32, z.data(), 32);
  }

  // Randomized KeyGen using system CSPRNG
  static void keygen(std::span<uint8_t, PublicKeyBytes> pk, std::span<uint8_t, SecretKeyBytes> sk) {
    std::array<uint8_t, 32> d;
    std::array<uint8_t, 32> z;
    random_bytes(d);
    random_bytes(z);
    keygen_internal(pk, sk, d, z);
  }

  // Deterministic Encapsulation given message m (FIPS 203
  // ML-KEM.Encaps_internal)
  static void encaps_internal(std::span<uint8_t, CiphertextBytes> ct,
                              std::span<uint8_t, SharedSecretBytes> ss,
                              std::span<const uint8_t, PublicKeyBytes> pk,
                              std::span<const uint8_t, 32> m) {
    // 1. Compute H(pk)
    std::array<uint8_t, 32> h;
    sha3_256(pk, h);

    // 2. (K, r) = G(m || H(pk))
    std::array<uint8_t, 64> buf;
    std::array<uint8_t, 64> kr;
    std::memcpy(buf.data(), m.data(), 32);
    std::memcpy(buf.data() + 32, h.data(), 32);
    sha3_512(buf, kr);

    std::span<const uint8_t, 32> k_share(kr.data(), 32);
    std::span<const uint8_t, 32> r_coins(kr.data() + 32, 32);

    // 3. ct = K-PKE.Encrypt(pk, m, r)
    indcpa_enc<K, Eta1, Eta2, Du, Dv>(ct, m, pk, r_coins);

    // 4. Return shared secret K
    std::memcpy(ss.data(), k_share.data(), SharedSecretBytes);
  }

  // Randomized Encapsulation using system CSPRNG
  static void encaps(std::span<uint8_t, CiphertextBytes> ct,
                     std::span<uint8_t, SharedSecretBytes> ss,
                     std::span<const uint8_t, PublicKeyBytes> pk) {
    std::array<uint8_t, 32> m;
    random_bytes(m);
    encaps_internal(ct, ss, pk, m);
  }

  // Decapsulation with Fujisaki-Okamoto implicit rejection (FIPS 203
  // ML-KEM.Decaps_internal)
  static void decaps(std::span<uint8_t, SharedSecretBytes> ss,
                     std::span<const uint8_t, CiphertextBytes> ct,
                     std::span<const uint8_t, SecretKeyBytes> sk) {
    // 1. Unpack sk components
    std::span<const uint8_t, 384 * K> sk_pke(sk.data(), 384 * K);
    std::span<const uint8_t, PublicKeyBytes> pk(sk.data() + 384 * K, PublicKeyBytes);
    std::span<const uint8_t, 32> h(sk.data() + 384 * K + PublicKeyBytes, 32);
    std::span<const uint8_t, 32> z(sk.data() + 384 * K + PublicKeyBytes + 32, 32);

    // 2. m' = K-PKE.Decrypt(sk_pke, ct)
    std::array<uint8_t, 32> m_prime;
    indcpa_dec<K, Du, Dv>(m_prime, ct, sk_pke);

    // 3. (K', r') = G(m' || h)
    std::array<uint8_t, 64> buf;
    std::array<uint8_t, 64> kr_prime;
    std::memcpy(buf.data(), m_prime.data(), 32);
    std::memcpy(buf.data() + 32, h.data(), 32);
    sha3_512(buf, kr_prime);

    std::span<const uint8_t, 32> k_prime(kr_prime.data(), 32);
    std::span<const uint8_t, 32> r_prime(kr_prime.data() + 32, 32);

    // 4. K_rej = J(z || ct) using SHAKE-256
    std::vector<uint8_t> zct(32 + CiphertextBytes);
    std::memcpy(zct.data(), z.data(), 32);
    std::memcpy(zct.data() + 32, ct.data(), CiphertextBytes);
    std::array<uint8_t, 32> k_rej;
    shake256(zct, k_rej);

    // 5. ct' = K-PKE.Encrypt(pk, m', r')
    std::array<uint8_t, CiphertextBytes> ct_prime;
    indcpa_enc<K, Eta1, Eta2, Du, Dv>(ct_prime, m_prime, pk, r_prime);

    // 6. Constant-time verification & implicit rejection multiplexing
    uint8_t diff = 0;
    for (size_t i = 0; i < CiphertextBytes; ++i) {
      diff = static_cast<uint8_t>(diff | (ct[i] ^ ct_prime[i]));
    }

    // If diff == 0, mask = 0x00; if diff != 0, mask = 0xFF
    uint8_t mask = static_cast<uint8_t>((static_cast<uint16_t>(diff) - 1) >> 8) ^ 0xFF;

    for (size_t i = 0; i < SharedSecretBytes; ++i) {
      ss[i] = static_cast<uint8_t>((k_prime[i] & ~mask) | (k_rej[i] & mask));
    }
  }
};

using MlKem512 = MlKem<2, 3, 2, 10, 4>;
using MlKem768 = MlKem<3, 2, 2, 10, 4>;
using MlKem1024 = MlKem<4, 2, 2, 11, 5>;

}  // namespace kem
