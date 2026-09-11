#pragma once

#include <array>
#include <span>

#include "kem/poly.hpp"

namespace kem {

template <size_t K>
struct PolyVec {
  static constexpr size_t Dimension = K;
  static constexpr size_t ByteSize = 384 * K;

  std::array<Poly, K> vec{};

  Poly& operator[](size_t i) { return vec[i]; }
  const Poly& operator[](size_t i) const { return vec[i]; }
};

template <size_t K>
void polyvec_compress(const PolyVec<K>& p, size_t du, std::span<uint8_t> r);

template <size_t K>
void polyvec_decompress(PolyVec<K>& r, size_t du, std::span<const uint8_t> a);

template <size_t K>
void polyvec_tobytes(std::span<uint8_t> r, const PolyVec<K>& a);

template <size_t K>
void polyvec_frombytes(PolyVec<K>& r, std::span<const uint8_t> a);

template <size_t K>
void polyvec_ntt(PolyVec<K>& r);

template <size_t K>
void polyvec_invntt(PolyVec<K>& r);

template <size_t K>
void polyvec_basemul_acc_montgomery(Poly& r, const PolyVec<K>& a, const PolyVec<K>& b);

template <size_t K>
void polyvec_reduce(PolyVec<K>& r);

template <size_t K>
void polyvec_add(PolyVec<K>& c, const PolyVec<K>& a, const PolyVec<K>& b);

using PolyVec2 = PolyVec<2>;
using PolyVec3 = PolyVec<3>;
using PolyVec4 = PolyVec<4>;

}  // namespace kem
