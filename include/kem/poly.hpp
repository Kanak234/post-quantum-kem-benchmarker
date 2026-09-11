#pragma once

#include <array>
#include <span>

#include "params.hpp"

namespace kem {

struct Poly {
  std::array<int16_t, KYBER_N> coeffs = {0};
};

void poly_compress(const Poly& p, size_t d, std::span<uint8_t> r);
void poly_decompress(Poly& r, size_t d, std::span<const uint8_t> a);

void poly_tobytes(std::span<uint8_t, 384> r, const Poly& a);
void poly_frombytes(Poly& r, std::span<const uint8_t, 384> a);

void poly_frommsg(Poly& r, std::span<const uint8_t, 32> msg);
void poly_tomsg(std::span<uint8_t, 32> msg, const Poly& a);

void poly_add(Poly& c, const Poly& a, const Poly& b);
void poly_sub(Poly& c, const Poly& a, const Poly& b);
void poly_reduce(Poly& a);
void poly_tomont(Poly& r);

void poly_ntt(Poly& p);
void poly_invntt(Poly& p);
void poly_basemul_montgomery(Poly& r, const Poly& a, const Poly& b);

}  // namespace kem
