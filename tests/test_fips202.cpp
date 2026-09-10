#include "kem/fips202.hpp"
#include <cassert>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace {

std::string to_hex(std::span<const uint8_t> data) {
  std::ostringstream oss;
  for (uint8_t b : data) {
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
  }
  return oss.str();
}

} // namespace

int main() {
  std::cout << "[TEST] Running FIPS 202 KAT Verification..." << std::endl;

  // Test 1: SHA3-256 empty string
  {
    std::array<uint8_t, 32> hash;
    kem::sha3_256(std::span<const uint8_t>{}, hash);
    std::string expected =
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    assert(to_hex(hash) == expected);
    std::cout << "  - SHA3-256(empty): PASSED" << std::endl;
  }

  // Test 2: SHA3-256 of "abc"
  {
    std::string input = "abc";
    std::array<uint8_t, 32> hash;
    kem::sha3_256(
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t *>(input.data()), input.size()),
        hash);
    std::string expected =
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
    assert(to_hex(hash) == expected);
    std::cout << "  - SHA3-256(\"abc\"): PASSED" << std::endl;
  }

  // Test 3: SHA3-512 empty string
  {
    std::array<uint8_t, 64> hash;
    kem::sha3_512(std::span<const uint8_t>{}, hash);
    std::string expected =
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b212"
        "3af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
    assert(to_hex(hash) == expected);
    std::cout << "  - SHA3-512(empty): PASSED" << std::endl;
  }

  // Test 4: SHA3-512 of "abc"
  {
    std::string input = "abc";
    std::array<uint8_t, 64> hash;
    kem::sha3_512(
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t *>(input.data()), input.size()),
        hash);
    std::string expected =
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116"
        "e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0";
    assert(to_hex(hash) == expected);
    std::cout << "  - SHA3-512(\"abc\"): PASSED" << std::endl;
  }

  // Test 5: SHAKE-128 and SHAKE-256 repeatability
  {
    std::string input = "The quick brown fox jumps over the lazy dog";
    std::array<uint8_t, 64> out1, out2;
    kem::shake128(
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t *>(input.data()), input.size()),
        out1);
    kem::shake128(
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t *>(input.data()), input.size()),
        out2);
    assert(out1 == out2);

    std::array<uint8_t, 64> out3, out4;
    kem::shake256(
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t *>(input.data()), input.size()),
        out3);
    kem::shake256(
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t *>(input.data()), input.size()),
        out4);
    assert(out3 == out4);
    assert(out1 != out3);
    std::cout << "  - SHAKE-128 / SHAKE-256 Squeeze: PASSED" << std::endl;
  }

  std::cout << "[TEST] All FIPS 202 tests passed!" << std::endl;
  return 0;
}
