#include "kem/cbd.hpp"

namespace kem {

void poly_cbd2(Poly &r, std::span<const uint8_t, 128> buf) {
  for (size_t i = 0; i < KYBER_N / 8; ++i) {
    uint32_t t = static_cast<uint32_t>(buf[4 * i + 0]) |
                 (static_cast<uint32_t>(buf[4 * i + 1]) << 8) |
                 (static_cast<uint32_t>(buf[4 * i + 2]) << 16) |
                 (static_cast<uint32_t>(buf[4 * i + 3]) << 24);

    uint32_t d = (t & 0x55555555U) + ((t >> 1) & 0x55555555U);

    for (size_t j = 0; j < 8; ++j) {
      int16_t a = static_cast<int16_t>((d >> (4 * j + 0)) & 0x3);
      int16_t b = static_cast<int16_t>((d >> (4 * j + 2)) & 0x3);
      r.coeffs[8 * i + j] = static_cast<int16_t>(a - b);
    }
  }
}

void poly_cbd3(Poly &r, std::span<const uint8_t, 192> buf) {
  for (size_t i = 0; i < KYBER_N / 4; ++i) {
    uint32_t t = static_cast<uint32_t>(buf[3 * i + 0]) |
                 (static_cast<uint32_t>(buf[3 * i + 1]) << 8) |
                 (static_cast<uint32_t>(buf[3 * i + 2]) << 16);

    uint32_t d =
        (t & 0x00249249U) + ((t >> 1) & 0x00249249U) + ((t >> 2) & 0x00249249U);

    for (size_t j = 0; j < 4; ++j) {
      int16_t a = static_cast<int16_t>((d >> (6 * j + 0)) & 0x7);
      int16_t b = static_cast<int16_t>((d >> (6 * j + 3)) & 0x7);
      r.coeffs[4 * i + j] = static_cast<int16_t>(a - b);
    }
  }
}

} // namespace kem
