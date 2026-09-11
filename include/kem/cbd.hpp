#pragma once

#include <span>

#include "kem/poly.hpp"

namespace kem {

// Samples polynomial with coefficients from centered binomial distribution eta
// = 2 Input: 128 bytes (64 * eta)
void poly_cbd2(Poly& r, std::span<const uint8_t, 128> buf);

// Samples polynomial with coefficients from centered binomial distribution eta
// = 3 Input: 192 bytes (64 * eta)
void poly_cbd3(Poly& r, std::span<const uint8_t, 192> buf);

}  // namespace kem
