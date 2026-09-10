#include "kem/ml_kem.hpp"
#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

namespace {

std::string to_hex_preview(std::span<const uint8_t> data,
                           size_t max_bytes = 16) {
  std::ostringstream oss;
  size_t count = std::min(data.size(), max_bytes);
  for (size_t i = 0; i < count; ++i) {
    oss << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(data[i]);
  }
  if (data.size() > max_bytes) {
    oss << "... (" << std::dec << data.size() << " bytes total)";
  }
  return oss.str();
}

void print_banner() {
  std::cout << R"(
=============================================================================
   NIST FIPS 203 ML-KEM (Post-Quantum Key Encapsulation) Explorer & Suite
=============================================================================
 [!] NOTICE: This codebase is engineered strictly for educational, research,
     and benchmarking purposes. Production deployments should rely on FIPS-
     validated HSMs or audited cryptographic libraries.
=============================================================================
)";
}

void print_usage(const char *prog) {
  print_banner();
  std::cout
      << "Usage:\n"
      << "  " << prog
      << " demo [512|768|1024]       Simulate Alice-Bob key encapsulation\n"
      << "  " << prog << " bench [512|768|1024|all]    Run microbenchmarks\n"
      << "  " << prog
      << " help                        Show this help message\n\n";
}

template <typename KemType> void run_demo(std::string_view name) {
  std::cout << "\n>>> Simulating Key Encapsulation Mechanism with " << name
            << " <<<\n\n";

  alignas(64) std::array<uint8_t, KemType::PublicKeyBytes> pk{};
  alignas(64) std::array<uint8_t, KemType::SecretKeyBytes> sk{};
  alignas(64) std::array<uint8_t, KemType::CiphertextBytes> ct{};
  alignas(64) std::array<uint8_t, KemType::SharedSecretBytes> ss_bob{};
  alignas(64) std::array<uint8_t, KemType::SharedSecretBytes> ss_alice{};

  // Step 1: Alice KeyGen
  std::cout << "[Alice] Generating post-quantum keypair...\n";
  auto t0 = std::chrono::high_resolution_clock::now();
  KemType::keygen(pk, sk);
  auto t1 = std::chrono::high_resolution_clock::now();
  double keygen_us = std::chrono::duration<double, std::micro>(t1 - t0).count();

  std::cout << "  - Public Key  (" << KemType::PublicKeyBytes
            << " bytes):  " << to_hex_preview(pk) << "\n";
  std::cout << "  - Secret Key  (" << KemType::SecretKeyBytes
            << " bytes): " << to_hex_preview(sk) << "\n";
  std::cout << "  - KeyGen time: " << std::fixed << std::setprecision(1)
            << keygen_us << " us\n\n";

  // Step 2: Bob Encapsulation
  std::cout
      << "[Bob] Encapsulating shared secret against Alice's public key...\n";
  auto t2 = std::chrono::high_resolution_clock::now();
  KemType::encaps(ct, ss_bob, pk);
  auto t3 = std::chrono::high_resolution_clock::now();
  double encaps_us = std::chrono::duration<double, std::micro>(t3 - t2).count();

  std::cout << "  - Ciphertext  (" << KemType::CiphertextBytes
            << " bytes):  " << to_hex_preview(ct) << "\n";
  std::cout << "  - Bob Secret  (32 bytes):   " << to_hex_preview(ss_bob, 32)
            << "\n";
  std::cout << "  - Encaps time: " << std::fixed << std::setprecision(1)
            << encaps_us << " us\n\n";

  // Step 3: Alice Decapsulation
  std::cout << "[Alice] Decapsulating ciphertext using private key...\n";
  auto t4 = std::chrono::high_resolution_clock::now();
  KemType::decaps(ss_alice, ct, sk);
  auto t5 = std::chrono::high_resolution_clock::now();
  double decaps_us = std::chrono::duration<double, std::micro>(t5 - t4).count();

  std::cout << "  - Alice Secret (32 bytes):  " << to_hex_preview(ss_alice, 32)
            << "\n";
  std::cout << "  - Decaps time: " << std::fixed << std::setprecision(1)
            << decaps_us << " us\n";

  if (ss_bob == ss_alice) {
    std::cout << "\n[SUCCESS] Shared secrets MATCH perfectly! Secure symmetric "
                 "channel established.\n";
  } else {
    std::cerr << "\n[ERROR] Shared secrets MISMATCH!\n";
    return;
  }

  // Step 4: Chosen Ciphertext Tamper Rejection Test
  std::cout << "\n[Security Test] Simulating MITM active tamper attack on "
               "ciphertext...\n";
  auto ct_tampered = ct;
  ct_tampered[0] ^= 0xFF; // Modify first byte

  std::array<uint8_t, KemType::SharedSecretBytes> ss_tampered{};
  KemType::decaps(ss_tampered, ct_tampered, sk);

  std::cout << "  - Tampered Secret (32 bytes): "
            << to_hex_preview(ss_tampered, 32) << "\n";
  if (ss_tampered != ss_bob) {
    std::cout << "[SUCCESS] Implicit rejection active: Malicious ciphertext "
                 "produced pseudo-random garbage.\n\n";
  } else {
    std::cerr << "[FAIL] Tampered ciphertext accepted!\n\n";
  }
}

template <typename KemType>
void run_quick_bench(std::string_view name, size_t iters = 1000) {
  alignas(64) std::array<uint8_t, KemType::PublicKeyBytes> pk{};
  alignas(64) std::array<uint8_t, KemType::SecretKeyBytes> sk{};
  alignas(64) std::array<uint8_t, KemType::CiphertextBytes> ct{};
  alignas(64) std::array<uint8_t, KemType::SharedSecretBytes> ss{};

  KemType::keygen(pk, sk);
  KemType::encaps(ct, ss, pk);

  auto t0 = std::chrono::high_resolution_clock::now();
  for (size_t i = 0; i < iters; ++i) {
    KemType::keygen(pk, sk);
  }
  auto t1 = std::chrono::high_resolution_clock::now();
  for (size_t i = 0; i < iters; ++i) {
    KemType::encaps(ct, ss, pk);
  }
  auto t2 = std::chrono::high_resolution_clock::now();
  for (size_t i = 0; i < iters; ++i) {
    KemType::decaps(ss, ct, sk);
  }
  auto t3 = std::chrono::high_resolution_clock::now();

  double keygen_us =
      std::chrono::duration<double, std::micro>(t1 - t0).count() /
      static_cast<double>(iters);
  double encaps_us =
      std::chrono::duration<double, std::micro>(t2 - t1).count() /
      static_cast<double>(iters);
  double decaps_us =
      std::chrono::duration<double, std::micro>(t3 - t2).count() /
      static_cast<double>(iters);

  std::cout << "  * " << name << " (" << iters << " iters): "
            << "KeyGen: " << std::fixed << std::setprecision(1) << keygen_us
            << " us (" << static_cast<size_t>(1e6 / keygen_us) << " ops/s) | "
            << "Encaps: " << encaps_us << " us ("
            << static_cast<size_t>(1e6 / encaps_us) << " ops/s) | "
            << "Decaps: " << decaps_us << " us ("
            << static_cast<size_t>(1e6 / decaps_us) << " ops/s)\n";
}

} // namespace

int main(int argc, char *argv[]) {
  if (argc < 2) {
    print_usage(argv[0]);
    return 1;
  }

  std::string_view command = argv[1];

  if (command == "help" || command == "--help" || command == "-h") {
    print_usage(argv[0]);
    return 0;
  }

  if (command == "demo") {
    print_banner();
    std::string_view param = (argc >= 3) ? argv[2] : "768";
    if (param == "512") {
      run_demo<kem::MlKem512>("ML-KEM-512 (NIST Cat 1)");
    } else if (param == "768") {
      run_demo<kem::MlKem768>("ML-KEM-768 (NIST Cat 3)");
    } else if (param == "1024") {
      run_demo<kem::MlKem1024>("ML-KEM-1024 (NIST Cat 5)");
    } else {
      std::cerr << "Unknown parameter set: " << param
                << " (options: 512, 768, 1024)\n";
      return 1;
    }
    return 0;
  }

  if (command == "bench") {
    print_banner();
    std::cout
        << "Running ML-KEM In-Process Benchmarks (1,000 iterations each):\n\n";
    run_quick_bench<kem::MlKem512>("ML-KEM-512");
    run_quick_bench<kem::MlKem768>("ML-KEM-768");
    run_quick_bench<kem::MlKem1024>("ML-KEM-1024");
    std::cout << "\nFor full microbenchmarks with NTT/Keccak breakdowns, run "
                 "./benchmark_kem\n";
    return 0;
  }

  print_usage(argv[0]);
  return 1;
}
