#pragma once

#include <array>
#include <span>

#include "kem/polyvec.hpp"

namespace kem {

template <size_t K>
void gen_matrix(std::array<PolyVec<K>, K>& a, std::span<const uint8_t, 32> seed, bool transposed);

template <size_t K, size_t Eta1>
void indcpa_keypair(std::span<uint8_t> pk, std::span<uint8_t> sk,
                    std::span<const uint8_t, 32> seed);

template <size_t K, size_t Eta1, size_t Eta2, size_t Du, size_t Dv>
void indcpa_enc(std::span<uint8_t> ct, std::span<const uint8_t, 32> msg,
                std::span<const uint8_t> pk, std::span<const uint8_t, 32> coins);

template <size_t K, size_t Du, size_t Dv>
void indcpa_dec(std::span<uint8_t, 32> msg, std::span<const uint8_t> ct,
                std::span<const uint8_t> sk);

}  // namespace kem
