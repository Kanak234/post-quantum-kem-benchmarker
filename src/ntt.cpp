#include "kem/ntt.hpp"

#include "kem/reduce.hpp"

namespace kem {

// Precomputed powers of primitive root of unity zeta = 17 in bit-reversed
// Montgomery representation Reference: Crystals-Kyber / NIST FIPS 203 table
const int16_t ZETAS[128] = {
    -1044, -758,  -359,  -1517, 1493,  1422,  287,   202,   -171,  622,   1577,  182,   962,
    -1202, -1474, 1468,  573,   -1325, 264,   383,   -829,  1458,  -1602, -130,  -681,  1017,
    732,   608,   -1542, 411,   -205,  -1571, 1223,  652,   -552,  1015,  -1293, 1491,  -282,
    -1544, 516,   -8,    -320,  -666,  -1618, -1162, 126,   1469,  -853,  -90,   -271,  830,
    107,   -1421, -247,  -951,  -398,  961,   -1508, -725,  448,   -1065, 677,   -1275, -1103,
    430,   555,   843,   -1251, 871,   1550,  105,   422,   587,   177,   -235,  -291,  -460,
    1574,  1653,  -246,  778,   1159,  -147,  -777,  1483,  -602,  1119,  -1590, 644,   -872,
    349,   418,   329,   -156,  -75,   817,   1097,  603,   610,   1322,  -1285, -1465, 384,
    -1215, -136,  1218,  -1335, -874,  220,   -1187, -1659, -1185, -1530, -1278, 794,   -1510,
    -854,  -870,  478,   -108,  -308,  996,   991,   958,   -1460, 1522,  1628};

// Forward NTT (Cooley-Tukey butterfly)
void ntt(std::span<int16_t, KYBER_N> r) {
  size_t k = 1;
  for (size_t len = 128; len >= 2; len >>= 1) {
    for (size_t start = 0; start < KYBER_N; start += 2 * len) {
      int16_t zeta = ZETAS[k++];
      for (size_t j = start; j < start + len; ++j) {
        int16_t t = fqmul(zeta, r[j + len]);
        r[j + len] = static_cast<int16_t>(r[j] - t);
        r[j] = static_cast<int16_t>(r[j] + t);
      }
    }
  }
}

// Inverse NTT (Gentleman-Sande butterfly) with Montgomery multiplication
void invntt(std::span<int16_t, KYBER_N> r) {
  size_t k = 127;
  for (size_t len = 2; len <= 128; len <<= 1) {
    for (size_t start = 0; start < KYBER_N; start += 2 * len) {
      int16_t zeta = ZETAS[k--];
      for (size_t j = start; j < start + len; ++j) {
        int16_t t = r[j];
        r[j] = barrett_reduce(static_cast<int16_t>(t + r[j + len]));
        r[j + len] = static_cast<int16_t>(r[j + len] - t);
        r[j + len] = fqmul(zeta, r[j + len]);
      }
    }
  }

  constexpr int16_t f = 1441;  // (R^2 / 128) mod q
  for (size_t j = 0; j < KYBER_N; ++j) {
    r[j] = fqmul(r[j], f);
  }
}

// Multiplication of two linear polynomials modulo X^2 - zeta
void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta) {
  r[0] = fqmul(a[1], b[1]);
  r[0] = fqmul(r[0], zeta);
  r[0] = static_cast<int16_t>(r[0] + fqmul(a[0], b[0]));

  r[1] = fqmul(a[0], b[1]);
  r[1] = static_cast<int16_t>(r[1] + fqmul(a[1], b[0]));
}

}  // namespace kem
