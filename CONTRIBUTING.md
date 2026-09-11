# Contributing to post-quantum-kem-benchmarker

Thank you for your interest in contributing!

## Development Workflow

1. Create a dedicated branch off `main` (e.g., `feat/feature-name` or `prod-hardening`).
2. Adhere to Google C++ formatting standards:
   ```bash
   find include src tests benchmarks -name '*.hpp' -o -name '*.cpp' | xargs clang-format -i
   ```
3. Build and execute unit tests with coverage:
   ```bash
   cmake -B build -DCMAKE_BUILD_TYPE=Debug -DENABLE_COVERAGE=ON
   cmake --build build -j$(nproc)
   ctest --test-dir build --output-on-failure
   ```
4. Verify code coverage remains >=80% across all modules in `src/`.
5. Open a Pull Request targeting `main`. All CI checks and CodeQL analyses must pass.
