#include "kem/fips202.hpp"

#include <algorithm>
#include <cstring>

namespace kem {

namespace {

constexpr uint64_t KECCAK_ROUND_CONSTANTS[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

constexpr unsigned int RHO_OFFSETS[24] = {1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
                                          27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};

constexpr unsigned int PI_PERMUTATION[24] = {10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                                             15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1};

inline uint64_t rotl64(uint64_t x, unsigned int shift) {
  return (x << (shift & 63)) | (x >> ((64 - shift) & 63));
}

void keccak_f1600(uint64_t state[25]) {
  for (uint64_t rc : KECCAK_ROUND_CONSTANTS) {
    // Theta step
    uint64_t c[5];
    for (int i = 0; i < 5; ++i) {
      c[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
    }
    uint64_t d[5];
    for (int i = 0; i < 5; ++i) {
      d[i] = c[(i + 4) % 5] ^ rotl64(c[(i + 1) % 5], 1);
    }
    for (int i = 0; i < 25; ++i) {
      state[i] ^= d[i % 5];
    }

    // Rho and Pi steps
    uint64_t current = state[1];
    for (int i = 0; i < 24; ++i) {
      unsigned int dest = PI_PERMUTATION[i];
      uint64_t next = state[dest];
      state[dest] = rotl64(current, RHO_OFFSETS[i]);
      current = next;
    }

    // Chi step
    for (int j = 0; j < 25; j += 5) {
      uint64_t temp[5];
      for (int i = 0; i < 5; ++i) {
        temp[i] = state[j + i];
      }
      for (int i = 0; i < 5; ++i) {
        state[j + i] = temp[i] ^ ((~temp[(i + 1) % 5]) & temp[(i + 2) % 5]);
      }
    }

    // Iota step
    state[0] ^= rc;
  }
}

}  // namespace

void keccak_init(KeccakState& state) {
  std::fill(std::begin(state.s), std::end(state.s), 0ULL);
  state.pos = 0;
}

void keccak_absorb(KeccakState& state, size_t rate, std::span<const uint8_t> input) {
  size_t in_pos = 0;
  size_t len = input.size();

  while (in_pos < len) {
    if (state.pos == rate) {
      keccak_f1600(state.s);
      state.pos = 0;
    }
    size_t take = std::min(len - in_pos, rate - state.pos);
    for (size_t i = 0; i < take; ++i) {
      size_t word_idx = (state.pos + i) / 8;
      size_t byte_idx = (state.pos + i) % 8;
      state.s[word_idx] ^= static_cast<uint64_t>(input[in_pos + i]) << (8 * byte_idx);
    }
    state.pos += take;
    in_pos += take;
  }
}

void keccak_finalize(KeccakState& state, size_t rate, uint8_t domain_delim) {
  // Pad10*1
  size_t word_idx = state.pos / 8;
  size_t byte_idx = state.pos % 8;
  state.s[word_idx] ^= static_cast<uint64_t>(domain_delim) << (8 * byte_idx);

  size_t last_word = (rate - 1) / 8;
  size_t last_byte = (rate - 1) % 8;
  state.s[last_word] ^= 0x80ULL << (8 * last_byte);

  keccak_f1600(state.s);
  state.pos = 0;
}

void keccak_squeezeblocks(KeccakState& state, size_t rate, std::span<uint8_t> output) {
  size_t out_pos = 0;
  size_t len = output.size();

  while (out_pos < len) {
    if (state.pos == rate) {
      keccak_f1600(state.s);
      state.pos = 0;
    }
    size_t take = std::min(len - out_pos, rate - state.pos);
    for (size_t i = 0; i < take; ++i) {
      size_t word_idx = (state.pos + i) / 8;
      size_t byte_idx = (state.pos + i) % 8;
      output[out_pos + i] = static_cast<uint8_t>((state.s[word_idx] >> (8 * byte_idx)) & 0xFF);
    }
    state.pos += take;
    out_pos += take;
  }
}

void shake128(std::span<const uint8_t> input, std::span<uint8_t> output) {
  KeccakState state;
  keccak_init(state);
  keccak_absorb(state, SHAKE128_RATE, input);
  keccak_finalize(state, SHAKE128_RATE, 0x1F);
  keccak_squeezeblocks(state, SHAKE128_RATE, output);
}

void shake256(std::span<const uint8_t> input, std::span<uint8_t> output) {
  KeccakState state;
  keccak_init(state);
  keccak_absorb(state, SHAKE256_RATE, input);
  keccak_finalize(state, SHAKE256_RATE, 0x1F);
  keccak_squeezeblocks(state, SHAKE256_RATE, output);
}

void sha3_256(std::span<const uint8_t> input, std::span<uint8_t, 32> output) {
  KeccakState state;
  keccak_init(state);
  keccak_absorb(state, SHA3_256_RATE, input);
  keccak_finalize(state, SHA3_256_RATE, 0x06);
  keccak_squeezeblocks(state, SHA3_256_RATE, output);
}

void sha3_512(std::span<const uint8_t> input, std::span<uint8_t, 64> output) {
  KeccakState state;
  keccak_init(state);
  keccak_absorb(state, SHA3_512_RATE, input);
  keccak_finalize(state, SHA3_512_RATE, 0x06);
  keccak_squeezeblocks(state, SHA3_512_RATE, output);
}

}  // namespace kem
