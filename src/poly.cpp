#include "kem/poly.hpp"
#include "kem/ntt.hpp"
#include "kem/reduce.hpp"
#include <cstring>

namespace kem {

void poly_compress(const Poly &p, size_t d, std::span<uint8_t> r) {
  if (d == 4) {
    for (size_t i = 0; i < KYBER_N / 2; ++i) {
      uint8_t t[2];
      for (size_t j = 0; j < 2; ++j) {
        int16_t val = barrett_reduce(p.coeffs[2 * i + j]);
        if (val < 0)
          val = static_cast<int16_t>(val + KYBER_Q);
        uint32_t c = (static_cast<uint32_t>(val) << 4) + (KYBER_Q / 2);
        c = (c * 20159) >> 26; // c / KYBER_Q
        t[j] = static_cast<uint8_t>(c & 0x0F);
      }
      r[i] = static_cast<uint8_t>(t[0] | (t[1] << 4));
    }
  } else if (d == 5) {
    for (size_t i = 0; i < KYBER_N / 8; ++i) {
      uint8_t t[8];
      for (size_t j = 0; j < 8; ++j) {
        int16_t val = barrett_reduce(p.coeffs[8 * i + j]);
        if (val < 0)
          val = static_cast<int16_t>(val + KYBER_Q);
        uint32_t c = (static_cast<uint32_t>(val) << 5) + (KYBER_Q / 2);
        c = (c * 20159) >> 26;
        t[j] = static_cast<uint8_t>(c & 0x1F);
      }
      r[5 * i + 0] = static_cast<uint8_t>(t[0] | (t[1] << 5));
      r[5 * i + 1] =
          static_cast<uint8_t>((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
      r[5 * i + 2] = static_cast<uint8_t>((t[3] >> 1) | (t[4] << 4));
      r[5 * i + 3] =
          static_cast<uint8_t>((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
      r[5 * i + 4] = static_cast<uint8_t>((t[6] >> 2) | (t[7] << 3));
    }
  } else if (d == 10) {
    for (size_t i = 0; i < KYBER_N / 4; ++i) {
      uint16_t t[4];
      for (size_t j = 0; j < 4; ++j) {
        int16_t val = barrett_reduce(p.coeffs[4 * i + j]);
        if (val < 0)
          val = static_cast<int16_t>(val + KYBER_Q);
        uint64_t c = (static_cast<uint64_t>(val) << 10) + (KYBER_Q / 2);
        c = (c * 20159) >> 26;
        t[j] = static_cast<uint16_t>(c & 0x3FF);
      }
      r[5 * i + 0] = static_cast<uint8_t>(t[0] & 0xFF);
      r[5 * i + 1] = static_cast<uint8_t>((t[0] >> 8) | ((t[1] & 0x3F) << 2));
      r[5 * i + 2] = static_cast<uint8_t>((t[1] >> 6) | ((t[2] & 0x0F) << 4));
      r[5 * i + 3] = static_cast<uint8_t>((t[2] >> 4) | ((t[3] & 0x03) << 6));
      r[5 * i + 4] = static_cast<uint8_t>(t[3] >> 2);
    }
  } else if (d == 11) {
    for (size_t i = 0; i < KYBER_N / 8; ++i) {
      uint16_t t[8];
      for (size_t j = 0; j < 8; ++j) {
        int16_t val = barrett_reduce(p.coeffs[8 * i + j]);
        if (val < 0)
          val = static_cast<int16_t>(val + KYBER_Q);
        uint64_t c = (static_cast<uint64_t>(val) << 11) + (KYBER_Q / 2);
        c = (c * 20159) >> 26;
        t[j] = static_cast<uint16_t>(c & 0x7FF);
      }
      r[11 * i + 0] = static_cast<uint8_t>(t[0] & 0xFF);
      r[11 * i + 1] = static_cast<uint8_t>((t[0] >> 8) | ((t[1] & 0x1F) << 3));
      r[11 * i + 2] = static_cast<uint8_t>((t[1] >> 5) | ((t[2] & 0x03) << 6));
      r[11 * i + 3] = static_cast<uint8_t>((t[2] >> 2) & 0xFF);
      r[11 * i + 4] = static_cast<uint8_t>((t[2] >> 10) | ((t[3] & 0x7F) << 1));
      r[11 * i + 5] = static_cast<uint8_t>((t[3] >> 7) | ((t[4] & 0x0F) << 4));
      r[11 * i + 6] = static_cast<uint8_t>((t[4] >> 4) | ((t[5] & 0x01) << 7));
      r[11 * i + 7] = static_cast<uint8_t>((t[5] >> 1) & 0xFF);
      r[11 * i + 8] = static_cast<uint8_t>((t[5] >> 9) | ((t[6] & 0x3F) << 2));
      r[11 * i + 9] = static_cast<uint8_t>((t[6] >> 6) | ((t[7] & 0x07) << 5));
      r[11 * i + 10] = static_cast<uint8_t>(t[7] >> 3);
    }
  }
}

void poly_decompress(Poly &r, size_t d, std::span<const uint8_t> a) {
  if (d == 4) {
    for (size_t i = 0; i < KYBER_N / 2; ++i) {
      uint32_t t0 = a[i] & 0x0F;
      uint32_t t1 = (a[i] >> 4) & 0x0F;
      r.coeffs[2 * i + 0] = static_cast<int16_t>((t0 * KYBER_Q + 8) >> 4);
      r.coeffs[2 * i + 1] = static_cast<int16_t>((t1 * KYBER_Q + 8) >> 4);
    }
  } else if (d == 5) {
    for (size_t i = 0; i < KYBER_N / 8; ++i) {
      uint32_t t[8];
      t[0] = static_cast<uint32_t>(a[5 * i + 0] & 0x1F);
      t[1] = static_cast<uint32_t>((a[5 * i + 0] >> 5) | ((a[5 * i + 1] & 0x03) << 3));
      t[2] = static_cast<uint32_t>((a[5 * i + 1] >> 2) & 0x1F);
      t[3] = static_cast<uint32_t>((a[5 * i + 1] >> 7) | ((a[5 * i + 2] & 0x0F) << 1));
      t[4] = static_cast<uint32_t>((a[5 * i + 2] >> 4) | ((a[5 * i + 3] & 0x01) << 4));
      t[5] = static_cast<uint32_t>((a[5 * i + 3] >> 1) & 0x1F);
      t[6] = static_cast<uint32_t>((a[5 * i + 3] >> 6) | ((a[5 * i + 4] & 0x07) << 2));
      t[7] = static_cast<uint32_t>(a[5 * i + 4] >> 3);

      for (size_t j = 0; j < 8; ++j) {
        r.coeffs[8 * i + j] = static_cast<int16_t>((t[j] * KYBER_Q + 16) >> 5);
      }
    }
  } else if (d == 10) {
    for (size_t i = 0; i < KYBER_N / 4; ++i) {
      uint32_t t[4];
      t[0] = static_cast<uint32_t>(a[5 * i + 0]) |
             (static_cast<uint32_t>(a[5 * i + 1] & 0x03) << 8);
      t[1] = static_cast<uint32_t>(a[5 * i + 1] >> 2) |
             (static_cast<uint32_t>(a[5 * i + 2] & 0x0F) << 6);
      t[2] = static_cast<uint32_t>(a[5 * i + 2] >> 4) |
             (static_cast<uint32_t>(a[5 * i + 3] & 0x3F) << 4);
      t[3] = static_cast<uint32_t>(a[5 * i + 3] >> 6) |
             (static_cast<uint32_t>(a[5 * i + 4]) << 2);

      for (size_t j = 0; j < 4; ++j) {
        r.coeffs[4 * i + j] =
            static_cast<int16_t>((t[j] * KYBER_Q + 512) >> 10);
      }
    }
  } else if (d == 11) {
    for (size_t i = 0; i < KYBER_N / 8; ++i) {
      uint32_t t[8];
      t[0] = static_cast<uint32_t>(a[11 * i + 0]) |
             (static_cast<uint32_t>(a[11 * i + 1] & 0x07) << 8);
      t[1] = static_cast<uint32_t>(a[11 * i + 1] >> 3) |
             (static_cast<uint32_t>(a[11 * i + 2] & 0x3F) << 5);
      t[2] = static_cast<uint32_t>(a[11 * i + 2] >> 6) |
             (static_cast<uint32_t>(a[11 * i + 3]) << 2) |
             (static_cast<uint32_t>(a[11 * i + 4] & 0x01) << 10);
      t[3] = static_cast<uint32_t>(a[11 * i + 4] >> 1) |
             (static_cast<uint32_t>(a[11 * i + 5] & 0x0F) << 7);
      t[4] = static_cast<uint32_t>(a[11 * i + 5] >> 4) |
             (static_cast<uint32_t>(a[11 * i + 6] & 0x7F) << 4);
      t[5] = static_cast<uint32_t>(a[11 * i + 6] >> 7) |
             (static_cast<uint32_t>(a[11 * i + 7]) << 1) |
             (static_cast<uint32_t>(a[11 * i + 8] & 0x03) << 9);
      t[6] = static_cast<uint32_t>(a[11 * i + 8] >> 2) |
             (static_cast<uint32_t>(a[11 * i + 9] & 0x1F) << 6);
      t[7] = static_cast<uint32_t>(a[11 * i + 9] >> 5) |
             (static_cast<uint32_t>(a[11 * i + 10]) << 3);

      for (size_t j = 0; j < 8; ++j) {
        r.coeffs[8 * i + j] =
            static_cast<int16_t>((t[j] * KYBER_Q + 1024) >> 11);
      }
    }
  }
}

// 12-bit encoding (384 bytes)
void poly_tobytes(std::span<uint8_t, 384> r, const Poly &a) {
  for (size_t i = 0; i < KYBER_N / 2; ++i) {
    uint16_t t0 = static_cast<uint16_t>(barrett_reduce(a.coeffs[2 * i + 0]));
    uint16_t t1 = static_cast<uint16_t>(barrett_reduce(a.coeffs[2 * i + 1]));
    if (static_cast<int16_t>(t0) < 0)
      t0 = static_cast<uint16_t>(t0 + KYBER_Q);
    if (static_cast<int16_t>(t1) < 0)
      t1 = static_cast<uint16_t>(t1 + KYBER_Q);

    r[3 * i + 0] = static_cast<uint8_t>(t0 & 0xFF);
    r[3 * i + 1] = static_cast<uint8_t>((t0 >> 8) | ((t1 & 0x0F) << 4));
    r[3 * i + 2] = static_cast<uint8_t>(t1 >> 4);
  }
}

void poly_frombytes(Poly &r, std::span<const uint8_t, 384> a) {
  for (size_t i = 0; i < KYBER_N / 2; ++i) {
    uint16_t t0 = static_cast<uint16_t>(
        static_cast<uint16_t>(a[3 * i + 0]) |
        static_cast<uint16_t>((a[3 * i + 1] & 0x0F) << 8));
    uint16_t t1 = static_cast<uint16_t>(
        static_cast<uint16_t>(a[3 * i + 1] >> 4) |
        static_cast<uint16_t>(a[3 * i + 2] << 4));
    r.coeffs[2 * i + 0] = static_cast<int16_t>(t0);
    r.coeffs[2 * i + 1] = static_cast<int16_t>(t1);
  }
}

void poly_frommsg(Poly &r, std::span<const uint8_t, 32> msg) {
  for (size_t i = 0; i < KYBER_N / 8; ++i) {
    for (size_t j = 0; j < 8; ++j) {
      int16_t mask =
          static_cast<int16_t>(-static_cast<int>((msg[i] >> j) & 1));
      r.coeffs[8 * i + j] = mask & ((KYBER_Q + 1) / 2);
    }
  }
}

void poly_tomsg(std::span<uint8_t, 32> msg, const Poly &a) {
  for (size_t i = 0; i < KYBER_N / 8; ++i) {
    msg[i] = 0;
    for (size_t j = 0; j < 8; ++j) {
      uint32_t t = static_cast<uint32_t>(barrett_reduce(a.coeffs[8 * i + j]));
      if (static_cast<int32_t>(t) < 0)
        t += KYBER_Q;
      t = ((t << 1) + (KYBER_Q / 2)) / KYBER_Q;
      msg[i] |= static_cast<uint8_t>((t & 1) << j);
    }
  }
}

void poly_add(Poly &c, const Poly &a, const Poly &b) {
  for (size_t i = 0; i < KYBER_N; ++i) {
    c.coeffs[i] = static_cast<int16_t>(a.coeffs[i] + b.coeffs[i]);
  }
}

void poly_sub(Poly &c, const Poly &a, const Poly &b) {
  for (size_t i = 0; i < KYBER_N; ++i) {
    c.coeffs[i] = static_cast<int16_t>(a.coeffs[i] - b.coeffs[i]);
  }
}

void poly_reduce(Poly &a) {
  for (size_t i = 0; i < KYBER_N; ++i) {
    a.coeffs[i] = barrett_reduce(a.coeffs[i]);
  }
}

void poly_ntt(Poly &p) {
  ntt(p.coeffs);
  poly_reduce(p);
}

void poly_invntt(Poly &p) { invntt(p.coeffs); }

void poly_basemul_montgomery(Poly &r, const Poly &a, const Poly &b) {
  for (size_t i = 0; i < KYBER_N / 4; ++i) {
    basemul(&r.coeffs[4 * i], &a.coeffs[4 * i], &b.coeffs[4 * i],
            ZETAS[64 + i]);
    basemul(&r.coeffs[4 * i + 2], &a.coeffs[4 * i + 2], &b.coeffs[4 * i + 2],
            static_cast<int16_t>(-ZETAS[64 + i]));
  }
}

void poly_tomont(Poly &r) {
  constexpr int16_t f = 1353; // (2^32) mod 3329
  for (size_t i = 0; i < KYBER_N; ++i) {
    r.coeffs[i] = montgomery_reduce(static_cast<int32_t>(r.coeffs[i]) * f);
  }
}

} // namespace kem
