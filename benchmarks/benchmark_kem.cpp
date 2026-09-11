#include <chrono>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "kem/fips202.hpp"
#include "kem/ml_kem.hpp"
#include "kem/ntt.hpp"
#include "kem/poly.hpp"

namespace {

using Clock = std::chrono::high_resolution_clock;

struct BenchmarkResult {
  std::string operation;
  size_t iterations;
  double total_ms;
  double ops_per_sec;
  double avg_us;
};

void print_header() {
  std::cout << "\n============================================================="
               "============================\n";
  std::cout << "                 NIST FIPS 203 ML-KEM (KYBER) MICROBENCHMARK "
               "HARNESS                     \n";
  std::cout << "==============================================================="
               "==========================\n";
  std::cout << std::left << std::setw(30) << "Benchmark Operation" << std::right << std::setw(14)
            << "Iterations" << std::setw(16) << "Total (ms)" << std::setw(16) << "Ops / Sec"
            << std::setw(14) << "Avg (us)"
            << "\n";
  std::cout << "---------------------------------------------------------------"
               "--------------------------\n";
}

void print_row(const BenchmarkResult& res) {
  std::cout << std::left << std::setw(30) << res.operation << std::right << std::setw(14)
            << res.iterations << std::fixed << std::setprecision(2) << std::setw(16) << res.total_ms
            << std::setw(16) << res.ops_per_sec << std::setw(14) << res.avg_us << "\n";
}

template <typename Func>
BenchmarkResult run_benchmark(const std::string& name, size_t iterations, Func&& func) {
  // Warmup
  for (size_t i = 0; i < std::min<size_t>(iterations / 10 + 1, 50); ++i) {
    func();
  }

  auto start = Clock::now();
  for (size_t i = 0; i < iterations; ++i) {
    func();
  }
  auto end = Clock::now();

  double total_ns = static_cast<double>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
  double total_ms = total_ns / 1'000'000.0;
  double avg_us = (total_ns / static_cast<double>(iterations)) / 1'000.0;
  double ops_per_sec = (static_cast<double>(iterations) / total_ns) * 1'000'000'000.0;

  BenchmarkResult res{name, iterations, total_ms, ops_per_sec, avg_us};
  print_row(res);
  return res;
}

template <typename KemType>
void benchmark_kem_suite(const std::string& name, size_t iters) {
  alignas(64) std::array<uint8_t, KemType::PublicKeyBytes> pk{};
  alignas(64) std::array<uint8_t, KemType::SecretKeyBytes> sk{};
  alignas(64) std::array<uint8_t, KemType::CiphertextBytes> ct{};
  alignas(64) std::array<uint8_t, KemType::SharedSecretBytes> ss{};

  KemType::keygen(pk, sk);
  KemType::encaps(ct, ss, pk);

  run_benchmark(name + " KeyGen", iters, [&]() { KemType::keygen(pk, sk); });

  run_benchmark(name + " Encaps", iters, [&]() { KemType::encaps(ct, ss, pk); });

  run_benchmark(name + " Decaps", iters, [&]() { KemType::decaps(ss, ct, sk); });
}

}  // namespace

int main() {
  print_header();

  // 1. NTT benchmarks
  {
    kem::Poly p{};
    for (size_t i = 0; i < kem::KYBER_N; ++i) p.coeffs[i] = static_cast<int16_t>(i);

    run_benchmark("Poly NTT (Forward)", 20000, [&]() { kem::poly_ntt(p); });

    run_benchmark("Poly InvNTT (Inverse)", 20000, [&]() { kem::poly_invntt(p); });
  }

  // 2. Symmetric Keccak / SHA3-256
  {
    std::array<uint8_t, 1024> buf{};
    std::array<uint8_t, 32> out{};
    run_benchmark("SHA3-256 (1 KiB)", 10000, [&]() { kem::sha3_256(buf, out); });
  }

  std::cout << "---------------------------------------------------------------"
               "--------------------------\n";

  // 3. ML-KEM Parameter Suites
  benchmark_kem_suite<kem::MlKem512>("ML-KEM-512", 2000);
  benchmark_kem_suite<kem::MlKem768>("ML-KEM-768", 2000);
  benchmark_kem_suite<kem::MlKem1024>("ML-KEM-1024", 2000);

  std::cout << "==============================================================="
               "==========================\n\n";
  return 0;
}
