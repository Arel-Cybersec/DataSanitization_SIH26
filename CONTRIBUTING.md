# Contributing to EraseCure

Thank you for your interest in contributing to EraseCure!

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Guidelines](#development-guidelines)
- [Pull Request Process](#pull-request-process)
- [Safety Requirements](#safety-requirements)

---

## Code of Conduct

Be respectful, constructive, and professional.  
This is a security-oriented project — claims and implementations must be
technically honest.

---

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork:
   ```bash
   git clone https://github.com/YOUR-USERNAME/erasecure.git
   cd erasecure/secure_eraser
   ```
3. **Install dependencies** (Ubuntu/Debian):
   ```bash
   sudo apt-get install build-essential cmake libssl-dev libsqlite3-dev
   ```
4. **Build** in Debug mode:
   ```bash
   cmake -B build -DCMAKE_BUILD_TYPE=Debug
   cmake --build build --parallel
   ```
5. **Run tests**:
   ```bash
   cd build && ctest --output-on-failure
   ```

---

## How to Contribute

### Reporting Bugs

Open a GitHub Issue using the **Bug Report** template.  
Include:
- OS and kernel version
- GCC/Clang version
- Steps to reproduce
- Expected vs actual behaviour
- Compiler output or test failure log

### Suggesting Features

Open a GitHub Issue using the **Feature Request** template.  
For security-sensitive features (new sanitization methods, crypto operations),
explain the technical basis and reference relevant standards (NIST SP 800-88,
ATA/NVMe specifications).

### Contributing Code

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Write code following the development guidelines below.
3. Add or update unit tests in `tests/`.
4. Ensure all tests pass with no sanitizer errors.
5. Open a Pull Request.

---

## Development Guidelines

### Language & Standard

- **C17 only.** No C++, Python, shell scripts, or other languages in `src/`.
- Use POSIX APIs where applicable.
- External libraries: OpenSSL (crypto only), SQLite3 (persistence only),
  pthreads (async operations).

### Code Style

- 4-space indentation (no tabs).
- `snake_case` for functions, variables, and struct members.
- `UPPER_CASE` for macros and enum values.
- Every public function documented with a `@brief` Doxygen comment.
- Include guards on every header: `#ifndef ERASECURE_<MODULE>_H`.

### Security Requirements (Non-Negotiable)

- **No unchecked `malloc()`** — always check for NULL.
- **No unchecked `read()`/`write()` lengths** — validate return values.
- **No hard-coded device paths** (`/dev/sda` etc.).
- **No silent destructive operations** — all writes must be explicit and logged.
- **No fake security claims** — if an operation only achieves logical erasure,
  say so clearly in code comments and result structs.
- Physical block devices must be blocked in test-mode functions.

### Compiler Flags

All code must compile cleanly under:
```
-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2
-fstack-protector-strong -D_FORTIFY_SOURCE=2
-fsanitize=address,undefined  (Debug builds)
```

Zero warnings permitted on merge.

### Implementing New Sanitization Methods

Before implementing any destructive device operation:

1. **Document** the ATA/NVMe/SCSI command reference (with specification section).
2. **Implement** capability detection before the destructive command.
3. **Test** on a dedicated, expendable test device — never on a system disk.
4. **Add safety guards** that prevent running on unintended devices.
5. **Write unit tests** that verify the stub/not-implemented path.
6. **Do NOT claim** a method achieves more than it technically does.

---

## Pull Request Process

1. Ensure `ctest --output-on-failure` passes with zero failures.
2. Ensure no AddressSanitizer or UBSan errors under Debug build.
3. Update `README.md` if the feature changes the public API or CLI.
4. Reference any related Issues in the PR description.
5. A maintainer will review within 7 days.

---

## Safety Precautions for Reviewers

- **Never approve** code that issues destructive device operations without
  explicit safety guards, capability checks, and user confirmation.
- **Never approve** a "crypto erase" implementation that does not perform
  actual hardware key destruction.
- **Reject** any implementation claiming 100% data destruction guarantees
  without technical justification for the specific device and method.
