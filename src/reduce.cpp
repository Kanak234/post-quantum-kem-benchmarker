#include "kem/reduce.hpp"

namespace kem {

// Montgomery reduction: computes a * R^-1 mod q
// Input: a in [-q * 2^15, q * 2^15]
// Output: t in [-q, q]
int16_t montgomery_reduce(int32_t a) {
  int16_t u = static_cast<int16_t>(static_cast<uint32_t>(a) * static_cast<uint32_t>(QINV));
  int32_t t = static_cast<int32_t>(u) * KYBER_Q;
  t = a - t;
  t >>= 16;
  return static_cast<int16_t>(t);
}

// Barrett reduction: computes a mod q
// Input: a in [-2^15, 2^15]
// Output: t in [-q, q] centered around 0
int16_t barrett_reduce(int16_t a) {
  constexpr int32_t v = (static_cast<int32_t>(1) << 26) / KYBER_Q + 1;  // 20159
  int32_t t = (v * static_cast<int32_t>(a) + (static_cast<int32_t>(1) << 25)) >> 26;
  t *= KYBER_Q;
  return static_cast<int16_t>(static_cast<int32_t>(a) - t);
}

// Multiplication in Z_q followed by Montgomery reduction
int16_t fqmul(int16_t a, int16_t b) {
  return montgomery_reduce(static_cast<int32_t>(a) * static_cast<int32_t>(b));
}

}  // namespace kem
