# EraseCure — Secure Data Sanitization Platform

> **Version**: 0.1.0-dev | **Language**: C17 | **Platform**: Linux

---

## Project Architecture

```
GUI/CLI  (future GTK / current CLI)
    ↓
Sanitization API          (sanitizer_run / sanitizer_supports_method)
    ↓
Device Abstraction        (StorageDevice, DeviceType, TransportType)
    ↓
Device-Specific Sanitizer (hdd_sanitizer / ssd_sanitizer / portable_sanitizer)
    ↓
Sanitization Method       (block_erase_image / crypto_erase_execute)
    ↓
Verification              (verify_image_pattern)
    ↓
Cryptographic Hashing     (hash_sha256 / hash_sha512 — OpenSSL EVP)
    ↓
Audit Logging             (audit_record_finalize — tamper-evident chain)
    ↓
Report / Database         (JSON-lines log + SQLite3)
```

The future GTK GUI will call the same public C APIs used by the CLI.  
No sanitization logic lives inside the CLI or GUI layers.

---

## Directory Structure

```
secure_eraser/
├── CMakeLists.txt
├── README.md
├── include/
│   ├── common/      types.h  constants.h  error.h
│   ├── device/      device.h  device_detect.h  device_info.h
│   ├── sanitization/sanitizer.h  block_erase.h  crypto_erase.h  verification.h
│   ├── hdd/         hdd_sanitizer.h
│   ├── ssd/         ssd_sanitizer.h
│   ├── portable/    portable_sanitizer.h
│   ├── crypto/      hash.h  key_management.h
│   ├── audit/       audit.h  audit_log.h
│   └── ui/          cli.h
├── src/
│   ├── main.c
│   ├── common/      constants.c  error.c
│   ├── device/      device.c  device_detect.c  device_info.c
│   ├── sanitization/sanitizer.c  block_erase.c  crypto_erase.c  verification.c
│   ├── hdd/         hdd_sanitizer.c
│   ├── ssd/         ssd_sanitizer.c
│   ├── portable/    portable_sanitizer.c
│   ├── crypto/      hash.c  key_management.c
│   ├── audit/       audit.c  audit_log.c
│   └── ui/          cli.c
├── tests/
│   ├── device_tests.c
│   ├── block_erase_tests.c
│   ├── crypto_erase_tests.c
│   └── verification_tests.c
├── data/
│   ├── logs/
│   └── reports/
└── build/
```

---

## Dependencies

| Library    | Purpose                          | Install (Debian/Ubuntu)                |
|------------|----------------------------------|----------------------------------------|
| OpenSSL    | SHA-256, SHA-512, CSPRNG         | `sudo apt-get install libssl-dev`      |
| SQLite3    | Persistent audit/case database   | `sudo apt-get install libsqlite3-dev`  |
| pthreads   | Future async operations          | Included with glibc                    |
| GTK 3      | Future GUI (optional)            | `sudo apt-get install libgtk-3-dev`    |
| CMake ≥3.16| Build system                     | `sudo apt-get install cmake`           |
| GCC/Clang  | C17 compiler                     | `sudo apt-get install build-essential` |

---

## Build Instructions

```bash
cd secure_eraser

# Configure (Debug — enables AddressSanitizer + UBSan)
cmake -B build -DCMAKE_BUILD_TYPE=Debug

# Build all targets
cmake --build build --parallel

# Run all tests
cd build && ctest --output-on-failure
```

**Release build** (no sanitizers, optimised):
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

**CLI binary location**: `build/bin/erasecure`

---

## CLI Usage

```bash
# List detected storage devices (Linux only, reads /sys/block)
./erasecure --list-devices

# Show detailed info about a device
./erasecure --info /dev/sda

# Erase a test image with zero pattern
./erasecure --test-image test.img --block-erase zero

# Erase with random pattern, 3 passes, verify after
./erasecure --test-image test.img --block-erase random --passes 3 --verify

# Verify an image contains zeros
./erasecure --verify-image test.img --pattern zero
```

**Create a test image first:**
```bash
dd if=/dev/zero of=test.img bs=1M count=10    # 10 MiB test image
```

---

## Device Discovery

EraseCure enumerates block devices by reading `/sys/block`.  
No external commands (`lsblk`, `fdisk`, etc.) are invoked.

Detection logic:
- **NVMe SSD**: device name starts with `nvme`
- **SD/MMC**: device name starts with `mmcblk`
- **USB**: `/sys/block/<dev>/device/subsystem` symlink contains `usb`
- **HDD vs SSD**: `/sys/block/<dev>/queue/rotational` (1=HDD, 0=SSD/flash)
- **USB HDD vs USB Flash**: USB interface + rotational flag

---

## Device Type Distinction

| DeviceType    | TransportType | Rotational | Description            |
|---------------|---------------|-----------|------------------------|
| HDD           | SATA          | Yes       | Mechanical hard disk   |
| SATA_SSD      | SATA          | No        | SATA solid-state drive |
| NVME_SSD      | NVMe          | No        | NVMe solid-state drive |
| USB_HDD       | USB           | Yes       | USB-attached HDD       |
| USB_SSD       | USB           | No        | USB-attached SSD       |
| USB_FLASH     | USB           | No        | USB flash drive        |
| SD_CARD       | SD            | No        | SD/microSD/MMC card    |

USB is an **interface**, not a storage medium.  
The architecture treats it as a transport layer, not a device type.

---

## Sanitization Architecture

### Block Erase (Implemented — Test Images Only)

Overwrites every byte of a **regular file** with a chosen pattern:

| Pattern | Fill value       | Notes                              |
|---------|------------------|------------------------------------|
| `zero`  | `0x00`          | Fast, deterministic, verifiable    |
| `one`   | `0xFF`          | Fast, deterministic, verifiable    |
| `random`| CSPRNG bytes    | OpenSSL `RAND_bytes()`, not verifiable by readback |

Multi-pass supported. fsync() called after each pass.  
**Path safety**: `/dev/*` paths are explicitly rejected.

### Cryptographic Erase (NOT IMPLEMENTED)

Cryptographic erase = **destruction of the hardware encryption key** on a  
Self-Encrypting Drive (SED).  After key destruction, stored ciphertext is  
computationally inaccessible.

This is **NOT**:
- Encrypting the disk with a new key
- Hashing disk contents
- Any software-only operation

Future implementation will require:
- SATA SED: `ATA SECURITY ERASE UNIT` (enhanced) via `SG_IO` ioctl
- NVMe SED: `Format NVM` (`ses=2`) or `Sanitize` via `NVME_IOCTL_ADMIN_CMD`

### Device-Native Sanitize (NOT IMPLEMENTED)

- SATA: `ATA Sanitize` command (`SANITIZE DEVICE`)
- NVMe: `NVMe Sanitize` or `Format NVM`

These commands trigger the device's internal erasure logic, which can  
physically erase NAND cells including over-provisioned areas.

---

## NAND Erasure Limitation

> **WARNING**: Logical block overwrite does NOT guarantee physical NAND erasure
> on SSDs, USB flash drives, or SD cards.
>
> The Flash Translation Layer (FTL) may transparently remap writes to new
> physical pages, leaving original data on unmapped NAND pages.
> Over-provisioned areas, bad block tables, and wear-levelling regions
> are inaccessible to host writes.
>
> EraseCure's verification layer explicitly states this in every
> `VerificationResult.confidence_note` for flash-based devices.

---

## Audit & Hash Chain

Every sanitization operation produces an `AuditRecord` containing:
- Case ID, Operation ID, Device identity, Capacity, Method, Pattern, Passes
- Start/end timestamps, Result codes, SHA-256 hashes
- Tamper-evident chain: `SHA256(canonical_fields + prev_hash) = this_record_hash`

Records are written as JSON lines to `data/logs/`.  
Persistent case metadata is stored in `data/erasecure_audit.db` (SQLite3).

Chain validation: `--validate-chain` (planned for next phase).

---

## What Is Implemented (v0.1.0-dev)

- [x] Complete directory and module structure
- [x] StorageDevice abstraction with all required types and enums
- [x] Linux device discovery via `/sys/block`
- [x] Device classification (HDD/SSD/NVMe/USB/SD)
- [x] Block erase on disk images (zero, one, random patterns)
- [x] Multi-pass support with fsync()
- [x] Progress callback API (GTK-ready)
- [x] Physical device path safety rejection
- [x] Post-erase verification (full and sampled readback)
- [x] SHA-256 and SHA-512 (OpenSSL EVP, buffers and files)
- [x] Tamper-evident audit hash chain
- [x] JSON-lines audit log
- [x] SQLite3 audit persistence
- [x] CLI: `--list-devices`, `--info`, `--test-image`, `--verify-image`
- [x] Unit tests (39 individual test cases)
- [x] CMake build with ASan/UBSan in Debug mode

## What Is Stubbed / Not Yet Implemented

- [ ] ATA Secure Erase (SECURITY ERASE UNIT) via SG_IO
- [ ] NVMe Sanitize / Format NVM via NVME_IOCTL_ADMIN_CMD
- [ ] SATA ATA Sanitize command
- [ ] SED key detection via ATA IDENTIFY DEVICE ioctl
- [ ] Real device block erase (requires root + careful safety layer)
- [ ] GTK GUI
- [ ] Secure File and Folder Eraser module
- [ ] Advanced File Carving and Recovery module
- [ ] PDF/HTML report generation
- [ ] `--validate-chain` CLI command

## What Should Be Implemented Next

1. **Real HDD block erase**: `BLKGETSIZE64` + direct fd write to block device (root required)
2. **ATA capability detection**: `SG_IO` + `HDIO_GET_IDENTITY` ioctl for security feature set
3. **NVMe capability detection**: `NVME_IOCTL_ADMIN_CMD` Identify Controller
4. **ATA Secure Erase stub → implementation**: Only after hardware testing
5. **Secure File/Folder Eraser**: `open()` + `write()` + `fsync()` + `unlink()` + metadata wipe
6. **GTK GUI**: Device list, progress bar, result display, using existing public APIs

---

## Safety Precautions

1. **Never run real-device operations without `--confirm-destructive` flag** (planned)
2. **Always test on image files before real hardware**
3. **Block erase path validation rejects `/dev/*` in test mode** — enforced in code
4. **Root privileges required for actual device access** — code checks uid
5. **No hard-coded device paths** — all paths come from user arguments or discovery
6. **SSD logical overwrite ≠ physical erasure** — stated in all result records

---

## Compliance Notes

EraseCure is designed with the following standards in mind:

- **NIST SP 800-88 Rev. 1** (Guidelines for Media Sanitization)
- **DoD 5220.22-M** (multi-pass overwrite — logical blocks only)

Block overwrite alone does **not** satisfy NIST Clear/Purge requirements for  
flash-based media.  Device-native sanitize commands are required for SSDs.

EraseCure never claims compliance it cannot technically demonstrate.

---

## License

EraseCure — Copyright (c) 2026 EraseCure Project.  
For academic/research use. See LICENSE file.
