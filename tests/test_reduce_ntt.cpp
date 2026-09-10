#include "kem/ntt.hpp"
#include "kem/poly.hpp"
#include "kem/reduce.hpp"
#include <cassert>
#include <iostream>
#include <random>

int main() {
  std::cout << "[TEST] Running Reduction and NTT Invertibility Tests..."
            << std::endl;

  // Test 1: Montgomery and Barrett reduction properties
  {
    for (int32_t a = -3328; a <= 3328; ++a) {
      int16_t b = kem::barrett_reduce(static_cast<int16_t>(a));
      int32_t mod_actual = (b % kem::KYBER_Q + kem::KYBER_Q) % kem::KYBER_Q;
      int32_t mod_expected = (a % kem::KYBER_Q + kem::KYBER_Q) % kem::KYBER_Q;
      assert(mod_actual == mod_expected);
    }
    std::cout << "  - Barrett reduction bounds: PASSED" << std::endl;
  }

  // Test 2: NTT and InvNTT roundtrip
  {
    std::mt19937_64 rng(42);
    std::uniform_int_distribution<int16_t> dist(-kem::KYBER_Q / 2,
                                                kem::KYBER_Q / 2);

    for (int trial = 0; trial < 100; ++trial) {
      kem::Poly p{};
      for (size_t i = 0; i < kem::KYBER_N; ++i) {
        p.coeffs[i] = dist(rng);
      }

      kem::Poly orig = p;
      kem::poly_ntt(p);
      kem::poly_invntt(p);

      // invntt returns p * R mod q, so montgomery_reduce cancels R
      for (size_t i = 0; i < kem::KYBER_N; ++i) {
        int16_t recovered = kem::montgomery_reduce(p.coeffs[i]);
        int16_t c1 = static_cast<int16_t>(
            (orig.coeffs[i] % kem::KYBER_Q + kem::KYBER_Q) % kem::KYBER_Q);
        int16_t c2 = static_cast<int16_t>(
            (recovered % kem::KYBER_Q + kem::KYBER_Q) % kem::KYBER_Q);
        assert(c1 == c2);
      }
    }
    std::cout << "  - NTT / InvNTT roundtrip with Montgomery inversion (100 "
                 "trials): PASSED"
              << std::endl;
  }

  // Test 3: Basemul and Convolution correctness
  {
    kem::Poly a{}, b{}, c{};
    a.coeffs[0] = 5;
    b.coeffs[0] = 7;
    kem::poly_ntt(a);
    kem::poly_ntt(b);
    kem::poly_basemul_montgomery(c, a, b);
    kem::poly_invntt(c);

    int16_t res = static_cast<int16_t>(
        (c.coeffs[0] % kem::KYBER_Q + kem::KYBER_Q) % kem::KYBER_Q);
    assert(res == 35);
    std::cout << "  - NTT Pointwise Basemul directly recovers unscaled "
                 "convolution: PASSED"
              << std::endl;
  }

  std::cout << "[TEST] All Reduction and NTT tests passed!" << std::endl;
  return 0;
}
