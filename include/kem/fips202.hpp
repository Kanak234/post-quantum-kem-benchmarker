#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace kem {

constexpr size_t SHAKE128_RATE = 168;
constexpr size_t SHAKE256_RATE = 136;
constexpr size_t SHA3_256_RATE = 136;
constexpr size_t SHA3_512_RATE = 72;

struct KeccakState {
  uint64_t s[25] = {0};
  size_t pos = 0;
};

void keccak_init(KeccakState& state);
void keccak_absorb(KeccakState& state, size_t rate, std::span<const uint8_t> input);
void keccak_finalize(KeccakState& state, size_t rate, uint8_t domain_delim);
void keccak_squeezeblocks(KeccakState& state, size_t rate, std::span<uint8_t> output);

// High-level API
void shake128(std::span<const uint8_t> input, std::span<uint8_t> output);
void shake256(std::span<const uint8_t> input, std::span<uint8_t> output);
void sha3_256(std::span<const uint8_t> input, std::span<uint8_t, 32> output);
void sha3_512(std::span<const uint8_t> input, std::span<uint8_t, 64> output);

}  // namespace kem
