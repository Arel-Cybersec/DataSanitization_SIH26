# DataSanitization — Secure Data Sanitization & Forensic Recovery Platform

> **Project**: Unified Data Sanitization and Forensic Carving Platform (SIH 2026)  
> **Core Engine**: **EraseCure** (Native C17)  
> **Target OS**: Linux (POSIX compliant)  

---

## 📌 Background & Mission

With the exponential expansion of digital storage technologies, organizations, defense units, law enforcement agencies, and cybersecurity investigators face two opposing challenges:
1. **Secure Data Sanitization**: Completely destroying sensitive digital data on physical and portable media to prevent unauthorized data recovery.
2. **Forensic Evidence Recovery**: Reconstructing and carving deleted digital evidence from formatted, damaged, or corrupted media during forensic investigations.

Existing tooling forces teams to use disjointed, unverified tools with limited device support. **DataSanitization** provides a unified, tamper-evident platform integrating:
- **Module 1**: Secure Drive Eraser (HDDs, SATA SSDs, NVMe SSDs, USB, SD/MMC)
- **Module 2**: Secure File & Folder Eraser (selective metadata cleansing & wiping)
- **Module 3**: Advanced File Carving & Recovery (signature and structure-based carving)

---

## 📂 Repository Structure

```
DataSanitization/
├── secure_eraser/                 # Core Sanitization Engine & CLI (EraseCure)
│   ├── CMakeLists.txt             # C17 CMake build system (ASan, UBSan, hardened)
│   ├── README.md                  # Comprehensive EraseCure technical documentation
│   ├── CHANGELOG.md               # Version history and changelog
│   ├── CONTRIBUTING.md            # Contribution guidelines and coding standards
│   ├── SECURITY.md                # Security policy & responsible disclosure
│   ├── LICENSE                    # MIT License with data sanitization disclaimer
│   │
│   ├── include/                   # Public modular headers
│   │   ├── common/                # types.h, constants.h, error.h
│   │   ├── device/                # device.h, device_detect.h, device_info.h
│   │   ├── sanitization/          # sanitizer.h, block_erase.h, crypto_erase.h, verification.h
│   │   ├── hdd/                   # hdd_sanitizer.h
│   │   ├── ssd/                   # ssd_sanitizer.h
│   │   ├── portable/              # portable_sanitizer.h
│   │   ├── crypto/                # hash.h, key_management.h
│   │   ├── audit/                 # audit.h, audit_log.h
│   │   └── ui/                    # cli.h
│   │
│   ├── src/                       # Production C17 implementations
│   │   ├── main.c                 # Entry point
│   │   ├── common/                # constants.c, error.c
│   │   ├── device/                # device.c, device_detect.c, device_info.c
│   │   ├── sanitization/          # sanitizer.c, block_erase.c, crypto_erase.c, verification.c
│   │   ├── hdd/                   # hdd_sanitizer.c
│   │   ├── ssd/                   # ssd_sanitizer.c
│   │   ├── portable/              # portable_sanitizer.c
│   │   ├── crypto/                # hash.c, key_management.c
│   │   ├── audit/                 # audit.c, audit_log.c
│   │   └── ui/                    # cli.c
│   │
│   ├── tests/                     # Automated test suites (37 unit tests)
│   │   ├── device_tests.c         # Struct init, type strings, /sys/block parser tests
│   │   ├── block_erase_tests.c    # Zero/one/random erase, multi-pass, safety tests
│   │   ├── crypto_erase_tests.c   # SED detection & stub safety tests
│   │   └── verification_tests.c   # Known-vector SHA-256/512, audit hash chain tests
│   │
│   └── data/                      # Audit logs and SQLite database directory
│       ├── logs/
│       └── reports/
│
├── .gitignore                     # Git ignore rules for build, test images, DBs
└── README.md                      # This root project overview
```

---

## ⚙️ Core Sanitization Engine (`secure_eraser`)

The core engine is implemented strictly in **C17** adhering to rigorous forensic and safety requirements:

1. **Hardware & Interface Discrimination**:
   - Accurately differentiates **HDD**, **SATA SSD**, **NVMe SSD**, **USB HDD**, **USB SSD**, **USB Flash**, and **SD Card**.
   - Treats USB as a transport interface, not a storage technology.

2. **Strict Safety Guard**:
   - Overwrite tests operate **only on regular test image files**.
   - Physical block devices (`/dev/sd*`, `/dev/nvme*`, `/dev/hd*`, etc.) are explicitly rejected in test mode to prevent accidental data destruction.

3. **NAND Flash Reality & Honesty**:
   - Clearly documents and reports that logical block overwriting does **not** guarantee physical NAND erasure on SSDs or Flash media due to the Flash Translation Layer (FTL), wear levelling, and over-provisioned blocks.
   - Distinct stubs and capability detection are reserved for device-native sanitize commands (`ATA SANITIZE`, `NVMe SANITIZE`).

4. **Tamper-Evident Audit Chain**:
   - Every sanitization operation generates a cryptographically hashed audit record using OpenSSL EVP SHA-256:
     $$\text{Hash}_n = \text{SHA256}(\text{Record}_n \,\|\, \text{Hash}_{n-1})$$
   - Persisted to both JSON-Lines log files and SQLite3 database tables.

---

## 🚀 Quick Build & Test (Linux)

### Prerequisites (Ubuntu / Debian)
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev libsqlite3-dev
```

### Build
```bash
cd secure_eraser
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
```

### Run Test Suites
```bash
cd build
ctest --output-on-failure
```

### CLI Quick Run
```bash
# 1. Create a dummy test image
dd if=/dev/zero of=test.img bs=1M count=10

# 2. Securely overwrite with random pattern & verify
./bin/erasecure --test-image test.img --block-erase random --passes 3 --verify

# 3. List detected storage devices on Linux
./bin/erasecure --list-devices
```

---

## 📜 Standards & Compliance Roadmap

- **NIST SP 800-88 Rev. 1**: Clear & Purge sanitization requirements
- **DoD 5220.22-M**: Overwrite sanitization patterns
- **ATA ACS-4 / NVMe 1.4+**: Device-native sanitize command compliance

---

## 📄 License

Licensed under the [MIT License](secure_eraser/LICENSE). Includes data sanitization and liability disclaimer.
