#pragma once

#include <span>

#include "params.hpp"

namespace kem {

// Twiddle factors in bit-reversed Montgomery representation
extern const int16_t ZETAS[128];

void ntt(std::span<int16_t, KYBER_N> r);
void invntt(std::span<int16_t, KYBER_N> r);
void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

}  // namespace kem
