#include <cassert>
#include <cmath>
#include <iostream>
#include <random>

#include "kem/poly.hpp"
#include "kem/reduce.hpp"

int main() {
  std::cout << "[TEST] Running Polynomial Serialization & Compression Tests..." << std::endl;

  // Test 1: 12-bit ByteEncode / ByteDecode (384 bytes) roundtrip
  {
    std::mt19937_64 rng(12345);
    std::uniform_int_distribution<int16_t> dist(0, kem::KYBER_Q - 1);

    for (int trial = 0; trial < 20; ++trial) {
      kem::Poly p{};
      for (size_t i = 0; i < kem::KYBER_N; ++i) {
        p.coeffs[i] = dist(rng);
      }

      std::array<uint8_t, 384> bytes{};
      kem::poly_tobytes(bytes, p);

      kem::Poly recovered{};
      kem::poly_frombytes(recovered, bytes);

      for (size_t i = 0; i < kem::KYBER_N; ++i) {
        assert(p.coeffs[i] == recovered.coeffs[i]);
      }
    }
    std::cout << "  - ByteEncode12 / ByteDecode12 (384 bytes): PASSED" << std::endl;
  }

  // Test 2: Message Encode / Decode (32 bytes) roundtrip
  {
    std::mt19937_64 rng(67890);
    std::uniform_int_distribution<uint16_t> dist(0, 255);

    for (int trial = 0; trial < 50; ++trial) {
      std::array<uint8_t, 32> msg{};
      for (size_t i = 0; i < 32; ++i) {
        msg[i] = static_cast<uint8_t>(dist(rng));
      }

      kem::Poly m_poly{};
      kem::poly_frommsg(m_poly, msg);

      std::array<uint8_t, 32> recovered_msg{};
      kem::poly_tomsg(recovered_msg, m_poly);

      assert(msg == recovered_msg);
    }
    std::cout << "  - Message ByteEncode1 / ByteDecode1 (32 bytes): PASSED" << std::endl;
  }

  // Test 3: Polynomial Compression and Decompression bounds
  {
    std::mt19937_64 rng(99999);
    std::uniform_int_distribution<int16_t> dist(0, kem::KYBER_Q - 1);

    auto test_compression = [&](size_t d, size_t out_bytes) {
      for (int trial = 0; trial < 10; ++trial) {
        kem::Poly p{};
        for (size_t i = 0; i < kem::KYBER_N; ++i) {
          p.coeffs[i] = dist(rng);
        }

        std::vector<uint8_t> compressed(out_bytes);
        kem::poly_compress(p, d, compressed);

        kem::Poly recovered{};
        kem::poly_decompress(recovered, d, compressed);

        // Check maximum rounding error bound: |x - round(x)| <= ceil(q /
        // 2^(d+1))
        int max_allowed_err = static_cast<int>(std::ceil(static_cast<double>(kem::KYBER_Q) /
                                                         static_cast<double>(1ULL << (d + 1)))) +
                              1;
        for (size_t i = 0; i < kem::KYBER_N; ++i) {
          int diff =
              std::abs(static_cast<int>(p.coeffs[i]) - static_cast<int>(recovered.coeffs[i]));
          if (diff > kem::KYBER_Q / 2) {
            diff = kem::KYBER_Q - diff;
          }
          assert(diff <= max_allowed_err);
        }
      }
    };

    test_compression(4, 128);
    test_compression(5, 160);
    test_compression(10, 320);
    test_compression(11, 352);
    std::cout << "  - Compression/Decompression Error Bounds (d in "
                 "{4,5,10,11}): PASSED"
              << std::endl;
  }

  std::cout << "[TEST] All Polynomial tests passed!" << std::endl;
  return 0;
}
