#include <cassert>
#include <iostream>
#include <random>
#include <vector>

#include "kem/ntt.hpp"
#include "kem/polyvec.hpp"
#include "kem/reduce.hpp"

template <size_t K>
void test_polyvec_operations() {
  std::cout << "  - Testing PolyVec<" << K << "> operations..." << std::endl;

  std::mt19937_64 rng(42 + K);
  std::uniform_int_distribution<int16_t> dist(-kem::KYBER_Q, kem::KYBER_Q * 2);

  kem::PolyVec<K> pv1{};
  kem::PolyVec<K> pv2{};

  for (size_t i = 0; i < K; ++i) {
    for (size_t n = 0; n < kem::KYBER_N; ++n) {
      pv1[i].coeffs[n] = dist(rng);
      pv2[i].coeffs[n] = dist(rng);
    }
  }

  // Const accessor check
  const auto& const_ref = pv1;
  for (size_t i = 0; i < K; ++i) {
    assert(const_ref[i].coeffs[0] == pv1[i].coeffs[0]);
  }

  // 1. polyvec_reduce
  kem::PolyVec<K> pv_red = pv1;
  kem::polyvec_reduce(pv_red);
  for (size_t i = 0; i < K; ++i) {
    for (size_t n = 0; n < kem::KYBER_N; ++n) {
      assert(pv_red[i].coeffs[n] >= -kem::KYBER_Q && pv_red[i].coeffs[n] <= kem::KYBER_Q);
    }
  }

  // 2. polyvec_add
  kem::PolyVec<K> pv_sum{};
  kem::polyvec_add(pv_sum, pv1, pv2);
  for (size_t i = 0; i < K; ++i) {
    for (size_t n = 0; n < kem::KYBER_N; ++n) {
      assert(pv_sum[i].coeffs[n] == static_cast<int16_t>(pv1[i].coeffs[n] + pv2[i].coeffs[n]));
    }
  }

  // 3. polyvec_ntt and polyvec_invntt
  kem::PolyVec<K> pv_ntt_orig{};
  for (size_t i = 0; i < K; ++i) {
    for (size_t n = 0; n < kem::KYBER_N; ++n) {
      pv_ntt_orig[i].coeffs[n] = static_cast<int16_t>(n % kem::KYBER_Q);
    }
  }
  kem::PolyVec<K> pv_transformed = pv_ntt_orig;
  kem::polyvec_ntt(pv_transformed);
  kem::polyvec_invntt(pv_transformed);

  for (size_t i = 0; i < K; ++i) {
    for (size_t n = 0; n < kem::KYBER_N; ++n) {
      int16_t recovered = kem::montgomery_reduce(pv_transformed[i].coeffs[n]);
      int16_t expected = static_cast<int16_t>(
          (pv_ntt_orig[i].coeffs[n] % kem::KYBER_Q + kem::KYBER_Q) % kem::KYBER_Q);
      int16_t actual =
          static_cast<int16_t>((recovered % kem::KYBER_Q + kem::KYBER_Q) % kem::KYBER_Q);
      assert(expected == actual);
    }
  }

  // 4. polyvec_tobytes and polyvec_frombytes
  std::vector<uint8_t> bytes(kem::PolyVec<K>::ByteSize);
  kem::PolyVec<K> pv_bytes_orig{};
  for (size_t i = 0; i < K; ++i) {
    for (size_t n = 0; n < kem::KYBER_N; ++n) {
      pv_bytes_orig[i].coeffs[n] = static_cast<int16_t>(dist(rng) % kem::KYBER_Q);
      if (pv_bytes_orig[i].coeffs[n] < 0) pv_bytes_orig[i].coeffs[n] += kem::KYBER_Q;
    }
  }
  kem::polyvec_tobytes(bytes, pv_bytes_orig);
  kem::PolyVec<K> pv_recovered{};
  kem::polyvec_frombytes(pv_recovered, bytes);
  for (size_t i = 0; i < K; ++i) {
    for (size_t n = 0; n < kem::KYBER_N; ++n) {
      assert(pv_bytes_orig[i].coeffs[n] == pv_recovered[i].coeffs[n]);
    }
  }

  // 5. polyvec_compress and polyvec_decompress
  size_t du = (K == 2 || K == 3) ? 10 : 11;
  std::vector<uint8_t> comp_bytes(32 * du * K);
  kem::polyvec_compress(pv_bytes_orig, du, comp_bytes);
  kem::PolyVec<K> pv_decomp{};
  kem::polyvec_decompress(pv_decomp, du, comp_bytes);

  // 6. polyvec_basemul_acc_montgomery
  kem::Poly acc{};
  kem::PolyVec<K> a_ntt = pv_bytes_orig;
  kem::PolyVec<K> b_ntt = pv_recovered;
  kem::polyvec_ntt(a_ntt);
  kem::polyvec_ntt(b_ntt);
  kem::polyvec_basemul_acc_montgomery(acc, a_ntt, b_ntt);

  std::cout << "    * PolyVec<" << K << "> all tests PASSED" << std::endl;
}

int main() {
  std::cout << "[TEST] Running PolyVec Edge Cases & Operations Suite..." << std::endl;
  test_polyvec_operations<2>();
  test_polyvec_operations<3>();
  test_polyvec_operations<4>();
  std::cout << "[TEST] PolyVec tests complete!" << std::endl;
  return 0;
}
