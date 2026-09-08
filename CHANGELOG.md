# Changelog — EraseCure

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Planned
- Real HDD block erase via direct block-device fd (root required)
- ATA IDENTIFY DEVICE capability detection via SG_IO
- ATA Secure Erase (SECURITY ERASE UNIT enhanced)
- NVMe Sanitize / Format NVM command support
- Secure File and Folder Eraser module
- GTK GUI (links same erasecure_core library)
- Advanced File Carving and Recovery module
- `--validate-chain` CLI command
- PDF/HTML audit report generation

---

## [0.1.0-dev] — 2026-09-06

### Added

#### Core Architecture
- Complete modular C17 project structure with 41 source files
- `erasecure_core` static library target (all modules)
- `erasecure_cli` executable target
- `erasecure_tests` test targets (4 test binaries, 37 test cases)
- CMake build system with OpenSSL, SQLite3, pthreads dependencies
- AddressSanitizer + UndefinedBehaviorSanitizer in Debug builds
- Strong compiler warning flags: `-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2`

#### Device Abstraction (`include/device/`, `src/device/`)
- `StorageDevice` structure with all required fields
- `DeviceType` enum: HDD, SATA_SSD, NVMe_SSD, USB_HDD, USB_SSD, USB_FLASH, SD_CARD
- `TransportType` enum: SATA, NVMe, USB, SD
- `SanitizationMethod` enum: BLOCK_ERASE, CRYPTO_ERASE, DEVICE_NATIVE
- Linux device discovery via `/sys/block` (no external commands)
- Device classification: NVMe (name prefix), SD/MMC (name prefix), USB (subsystem symlink), HDD vs SSD (rotational flag)
- Sysfs attribute reading: capacity, sector sizes, model, serial, removable, read-only flags
- Physical block-device path detection (prefix + `stat` S_ISBLK check)

#### Block Erase (`src/sanitization/block_erase.c`)
- Zero pattern (0x00), One pattern (0xFF), Random pattern (OpenSSL `RAND_bytes`)
- Multi-pass support (configurable, up to 35 passes)
- `fsync()` after each pass
- Progress callback API (GTK-ready)
- **Safety guard**: rejects any path matching `/dev/sd*`, `/dev/nvme*`, etc.
- Configurable block/chunk size (default 1 MiB)

#### Verification (`src/sanitization/verification.c`)
- Full readback verification (every block)
- Sampled readback verification (configurable sample count)
- Explicit NAND limitation note in every `VerificationResult.confidence_note`
- Random pattern: correctly refuses verification (non-deterministic)

#### Cryptographic Hashing (`src/crypto/hash.c`)
- SHA-256 and SHA-512 via OpenSSL EVP API
- Buffer hashing and file streaming hashing
- `hash_digest_to_hex()` conversion utility

#### Audit System (`src/audit/`)
- `AuditRecord` structure with all required fields (case ID, device identity, timestamps, hashes)
- Tamper-evident hash chain: `SHA256(canonical_fields + prev_hash)`
- JSON-lines audit log (append-only, one record per line)
- SQLite3 persistence with full schema and prepared statements
- Chain validation API

#### Sanitizer Modules
- `sanitizer_run()` central dispatcher (HDD → hdd_sanitizer, SSD → ssd_sanitizer, portable → portable_sanitizer)
- HDD sanitizer: test-image block erase implemented; ATA Secure Erase stubbed
- SSD sanitizer: SATA/NVMe distinction; NAND caveat documented; native ops stubbed
- Portable sanitizer: routes USB HDD → HDD module, USB SSD → SSD module, Flash/SD → block erase
- Crypto erase: capability query implemented; execution stubbed with detailed TODO comments
- Key management: SED detection stubbed pending `HDIO_GET_IDENTITY` ioctl

#### CLI (`src/ui/cli.c`)
- `--list-devices`: enumerate storage devices
- `--info <path>`: show device details
- `--test-image <file> --block-erase <zero|one|random>`: erase image
  - `--passes <N>`, `--block-size <N>`, `--verify`, `--verify-full`
- `--verify-image <file> --pattern <zero|one>`: verify image content
- `--help`: usage text
- Test-mode banner displayed on all destructive commands

#### Unit Tests (37 test cases)
- `device_tests`: struct init, type strings, path detection, classification
- `block_erase_tests`: safety guard, all patterns, multi-pass, byte count, verify pass/fail
- `crypto_erase_tests`: capability query, NOT_IMPLEMENTED stub, null safety
- `verification_tests`: SHA-256/SHA-512 known vectors, file hashing, audit chain, tamper detection

#### Documentation
- `README.md`: full architecture, build instructions, CLI usage, device classification table, NAND limitation warning
- `CONTRIBUTING.md`: development guidelines, security requirements, PR process
- `SECURITY.md`: vulnerability reporting policy, security architecture
- `CHANGELOG.md`: this file
- `.gitignore`: build artifacts, runtime files, IDE files
- `LICENSE`: MIT with data sanitization disclaimer

### Not Implemented (Phase 1 Scope)
- Real device write operations (all return `NOT_IMPLEMENTED`)
- ATA Secure Erase, ATA Sanitize
- NVMe Sanitize, NVMe Format NVM
- SED key detection via IDENTIFY DEVICE
- Secure File and Folder Eraser
- Advanced File Carving and Recovery
- GTK GUI
