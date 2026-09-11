#include "kem/indcpa.hpp"

#include <cstring>

#include "kem/cbd.hpp"
#include "kem/fips202.hpp"

namespace kem {

template <size_t K>
void gen_matrix(std::array<PolyVec<K>, K>& a, std::span<const uint8_t, 32> seed, bool transposed) {
  for (size_t i = 0; i < K; ++i) {
    for (size_t j = 0; j < K; ++j) {
      uint8_t extseed[34];
      std::memcpy(extseed, seed.data(), 32);
      if (transposed) {
        extseed[32] = static_cast<uint8_t>(i);
        extseed[33] = static_cast<uint8_t>(j);
      } else {
        extseed[32] = static_cast<uint8_t>(j);
        extseed[33] = static_cast<uint8_t>(i);
      }

      KeccakState state;
      keccak_init(state);
      keccak_absorb(state, SHAKE128_RATE, extseed);
      keccak_finalize(state, SHAKE128_RATE, 0x1F);

      size_t count = 0;
      uint8_t buf[SHAKE128_RATE];
      while (count < KYBER_N) {
        keccak_squeezeblocks(state, SHAKE128_RATE, buf);
        for (size_t pos = 0; pos + 3 <= SHAKE128_RATE && count < KYBER_N; pos += 3) {
          uint16_t d1 = static_cast<uint16_t>(buf[pos + 0] | ((buf[pos + 1] & 0x0F) << 8));
          uint16_t d2 = static_cast<uint16_t>((buf[pos + 1] >> 4) | (buf[pos + 2] << 4));
          if (d1 < KYBER_Q) {
            a[i][j].coeffs[count++] = static_cast<int16_t>(d1);
          }
          if (d2 < KYBER_Q && count < KYBER_N) {
            a[i][j].coeffs[count++] = static_cast<int16_t>(d2);
          }
        }
      }
    }
  }
}

namespace {

template <size_t Eta>
void sample_noise(Poly& p, std::span<const uint8_t, 32> seed, uint8_t nonce) {
  uint8_t extseed[33];
  std::memcpy(extseed, seed.data(), 32);
  extseed[32] = nonce;

  if constexpr (Eta == 2) {
    std::array<uint8_t, 128> buf;
    shake256(extseed, buf);
    poly_cbd2(p, buf);
  } else if constexpr (Eta == 3) {
    std::array<uint8_t, 192> buf;
    shake256(extseed, buf);
    poly_cbd3(p, buf);
  }
}

}  // namespace

template <size_t K, size_t Eta1>
void indcpa_keypair(std::span<uint8_t> pk, std::span<uint8_t> sk,
                    std::span<const uint8_t, 32> seed) {
  std::array<uint8_t, 64> buf;
  sha3_512(seed, buf);
  std::span<const uint8_t, 32> rho(buf.data(), 32);
  std::span<const uint8_t, 32> sigma(buf.data() + 32, 32);

  std::array<PolyVec<K>, K> a;
  gen_matrix<K>(a, rho, false);

  PolyVec<K> s, e;
  uint8_t nonce = 0;
  for (size_t i = 0; i < K; ++i) {
    sample_noise<Eta1>(s[i], sigma, nonce++);
  }
  for (size_t i = 0; i < K; ++i) {
    sample_noise<Eta1>(e[i], sigma, nonce++);
  }

  polyvec_ntt(s);
  polyvec_ntt(e);

  PolyVec<K> t;
  for (size_t i = 0; i < K; ++i) {
    polyvec_basemul_acc_montgomery(t[i], a[i], s);
    poly_tomont(t[i]);
    poly_add(t[i], t[i], e[i]);
    poly_reduce(t[i]);
  }

  polyvec_tobytes(pk.subspan(0, 384 * K), t);
  std::memcpy(pk.data() + 384 * K, rho.data(), 32);
  polyvec_tobytes(sk.subspan(0, 384 * K), s);
}

template <size_t K, size_t Eta1, size_t Eta2, size_t Du, size_t Dv>
void indcpa_enc(std::span<uint8_t> ct, std::span<const uint8_t, 32> msg,
                std::span<const uint8_t> pk, std::span<const uint8_t, 32> coins) {
  PolyVec<K> pk_t;
  polyvec_frombytes(pk_t, pk.subspan(0, 384 * K));
  std::span<const uint8_t, 32> rho(pk.data() + 384 * K, 32);

  std::array<PolyVec<K>, K> at;
  gen_matrix<K>(at, rho, true);

  PolyVec<K> sp;
  uint8_t nonce = 0;
  for (size_t i = 0; i < K; ++i) {
    sample_noise<Eta1>(sp[i], coins, nonce++);
  }

  PolyVec<K> ep;
  for (size_t i = 0; i < K; ++i) {
    sample_noise<Eta2>(ep[i], coins, nonce++);
  }

  Poly epp;
  sample_noise<Eta2>(epp, coins, nonce++);

  polyvec_ntt(sp);

  PolyVec<K> u;
  for (size_t i = 0; i < K; ++i) {
    polyvec_basemul_acc_montgomery(u[i], at[i], sp);
    poly_invntt(u[i]);
    poly_add(u[i], u[i], ep[i]);
    poly_reduce(u[i]);
  }

  Poly v;
  polyvec_basemul_acc_montgomery(v, pk_t, sp);
  poly_invntt(v);

  Poly k_poly;
  poly_frommsg(k_poly, msg);

  poly_add(v, v, epp);
  poly_add(v, v, k_poly);
  poly_reduce(v);

  size_t du_bytes = 32 * Du * K;
  size_t dv_bytes = 32 * Dv;
  polyvec_compress(u, Du, ct.subspan(0, du_bytes));
  poly_compress(v, Dv, ct.subspan(du_bytes, dv_bytes));
}

template <size_t K, size_t Du, size_t Dv>
void indcpa_dec(std::span<uint8_t, 32> msg, std::span<const uint8_t> ct,
                std::span<const uint8_t> sk) {
  PolyVec<K> u;
  size_t du_bytes = 32 * Du * K;
  size_t dv_bytes = 32 * Dv;

  polyvec_decompress(u, Du, ct.subspan(0, du_bytes));

  Poly v;
  poly_decompress(v, Dv, ct.subspan(du_bytes, dv_bytes));

  PolyVec<K> sk_s;
  polyvec_frombytes(sk_s, sk.subspan(0, 384 * K));

  polyvec_ntt(u);

  Poly mp;
  polyvec_basemul_acc_montgomery(mp, sk_s, u);
  poly_invntt(mp);

  Poly w;
  poly_sub(w, v, mp);
  poly_reduce(w);

  poly_tomsg(msg, w);
}

// Explicit template instantiations
template void gen_matrix<2>(std::array<PolyVec<2>, 2>&, std::span<const uint8_t, 32>, bool);
template void gen_matrix<3>(std::array<PolyVec<3>, 3>&, std::span<const uint8_t, 32>, bool);
template void gen_matrix<4>(std::array<PolyVec<4>, 4>&, std::span<const uint8_t, 32>, bool);

template void indcpa_keypair<2, 3>(std::span<uint8_t>, std::span<uint8_t>,
                                   std::span<const uint8_t, 32>);
template void indcpa_keypair<3, 2>(std::span<uint8_t>, std::span<uint8_t>,
                                   std::span<const uint8_t, 32>);
template void indcpa_keypair<4, 2>(std::span<uint8_t>, std::span<uint8_t>,
                                   std::span<const uint8_t, 32>);

template void indcpa_enc<2, 3, 2, 10, 4>(std::span<uint8_t>, std::span<const uint8_t, 32>,
                                         std::span<const uint8_t>, std::span<const uint8_t, 32>);
template void indcpa_enc<3, 2, 2, 10, 4>(std::span<uint8_t>, std::span<const uint8_t, 32>,
                                         std::span<const uint8_t>, std::span<const uint8_t, 32>);
template void indcpa_enc<4, 2, 2, 11, 5>(std::span<uint8_t>, std::span<const uint8_t, 32>,
                                         std::span<const uint8_t>, std::span<const uint8_t, 32>);

template void indcpa_dec<2, 10, 4>(std::span<uint8_t, 32>, std::span<const uint8_t>,
                                   std::span<const uint8_t>);
template void indcpa_dec<3, 10, 4>(std::span<uint8_t, 32>, std::span<const uint8_t>,
                                   std::span<const uint8_t>);
template void indcpa_dec<4, 11, 5>(std::span<uint8_t, 32>, std::span<const uint8_t>,
                                   std::span<const uint8_t>);

}  // namespace kem
