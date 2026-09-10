#include "kem/polyvec.hpp"

namespace kem {

template <size_t K>
void polyvec_compress(const PolyVec<K> &p, size_t du, std::span<uint8_t> r) {
  size_t poly_comp_len = 32 * du;
  for (size_t i = 0; i < K; ++i) {
    poly_compress(p[i], du, r.subspan(i * poly_comp_len, poly_comp_len));
  }
}

template <size_t K>
void polyvec_decompress(PolyVec<K> &r, size_t du, std::span<const uint8_t> a) {
  size_t poly_comp_len = 32 * du;
  for (size_t i = 0; i < K; ++i) {
    poly_decompress(r[i], du, a.subspan(i * poly_comp_len, poly_comp_len));
  }
}

template <size_t K>
void polyvec_tobytes(std::span<uint8_t> r, const PolyVec<K> &a) {
  for (size_t i = 0; i < K; ++i) {
    std::span<uint8_t, 384> slice(r.data() + i * 384, 384);
    poly_tobytes(slice, a[i]);
  }
}

template <size_t K>
void polyvec_frombytes(PolyVec<K> &r, std::span<const uint8_t> a) {
  for (size_t i = 0; i < K; ++i) {
    std::span<const uint8_t, 384> slice(a.data() + i * 384, 384);
    poly_frombytes(r[i], slice);
  }
}

template <size_t K> void polyvec_ntt(PolyVec<K> &r) {
  for (size_t i = 0; i < K; ++i) {
    poly_ntt(r[i]);
  }
}

template <size_t K> void polyvec_invntt(PolyVec<K> &r) {
  for (size_t i = 0; i < K; ++i) {
    poly_invntt(r[i]);
  }
}

template <size_t K>
void polyvec_basemul_acc_montgomery(Poly &r, const PolyVec<K> &a,
                                    const PolyVec<K> &b) {
  poly_basemul_montgomery(r, a[0], b[0]);
  Poly t;
  for (size_t i = 1; i < K; ++i) {
    poly_basemul_montgomery(t, a[i], b[i]);
    poly_add(r, r, t);
  }
  poly_reduce(r);
}

template <size_t K> void polyvec_reduce(PolyVec<K> &r) {
  for (size_t i = 0; i < K; ++i) {
    poly_reduce(r[i]);
  }
}

template <size_t K>
void polyvec_add(PolyVec<K> &c, const PolyVec<K> &a, const PolyVec<K> &b) {
  for (size_t i = 0; i < K; ++i) {
    poly_add(c[i], a[i], b[i]);
  }
}

// Explicit template instantiations for K = 2, 3, 4
template void polyvec_compress<2>(const PolyVec<2> &, size_t,
                                  std::span<uint8_t>);
template void polyvec_compress<3>(const PolyVec<3> &, size_t,
                                  std::span<uint8_t>);
template void polyvec_compress<4>(const PolyVec<4> &, size_t,
                                  std::span<uint8_t>);

template void polyvec_decompress<2>(PolyVec<2> &, size_t,
                                    std::span<const uint8_t>);
template void polyvec_decompress<3>(PolyVec<3> &, size_t,
                                    std::span<const uint8_t>);
template void polyvec_decompress<4>(PolyVec<4> &, size_t,
                                    std::span<const uint8_t>);

template void polyvec_tobytes<2>(std::span<uint8_t>, const PolyVec<2> &);
template void polyvec_tobytes<3>(std::span<uint8_t>, const PolyVec<3> &);
template void polyvec_tobytes<4>(std::span<uint8_t>, const PolyVec<4> &);

template void polyvec_frombytes<2>(PolyVec<2> &, std::span<const uint8_t>);
template void polyvec_frombytes<3>(PolyVec<3> &, std::span<const uint8_t>);
template void polyvec_frombytes<4>(PolyVec<4> &, std::span<const uint8_t>);

template void polyvec_ntt<2>(PolyVec<2> &);
template void polyvec_ntt<3>(PolyVec<3> &);
template void polyvec_ntt<4>(PolyVec<4> &);

template void polyvec_invntt<2>(PolyVec<2> &);
template void polyvec_invntt<3>(PolyVec<3> &);
template void polyvec_invntt<4>(PolyVec<4> &);

template void polyvec_basemul_acc_montgomery<2>(Poly &, const PolyVec<2> &,
                                                const PolyVec<2> &);
template void polyvec_basemul_acc_montgomery<3>(Poly &, const PolyVec<3> &,
                                                const PolyVec<3> &);
template void polyvec_basemul_acc_montgomery<4>(Poly &, const PolyVec<4> &,
                                                const PolyVec<4> &);

template void polyvec_reduce<2>(PolyVec<2> &);
template void polyvec_reduce<3>(PolyVec<3> &);
template void polyvec_reduce<4>(PolyVec<4> &);

template void polyvec_add<2>(PolyVec<2> &, const PolyVec<2> &,
                             const PolyVec<2> &);
template void polyvec_add<3>(PolyVec<3> &, const PolyVec<3> &,
                             const PolyVec<3> &);
template void polyvec_add<4>(PolyVec<4> &, const PolyVec<4> &,
                             const PolyVec<4> &);

} // namespace kem
