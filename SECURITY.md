# Security Policy — EraseCure

## Supported Versions

| Version     | Supported          |
|-------------|--------------------|
| 0.1.0-dev   | ✅ Active development |

---

## Reporting a Vulnerability

**Please do NOT open a public GitHub Issue for security vulnerabilities.**

If you discover a security vulnerability in EraseCure (e.g., a path-traversal
bug that could allow test-mode functions to write to real block devices, a
buffer overflow, or an audit chain bypass), please report it privately:

1. Open a **GitHub Security Advisory** (Advisories → Report a vulnerability)
   on the repository page.
2. Provide:
   - A clear description of the vulnerability
   - Steps to reproduce
   - Potential impact (e.g., data corruption, privilege escalation)
   - Suggested fix if you have one

We will acknowledge reports within **72 hours** and aim to release a fix
within **14 days** for critical issues.

---

## Security Architecture

EraseCure enforces the following security properties:

### Test-Mode Safety Guard
All destructive functions (`block_erase_image`, etc.) explicitly check whether
the provided path is a physical block device (via prefix matching against
`/dev/sd*`, `/dev/nvme*`, etc., and `stat()` `S_ISBLK` check).  Physical paths
are rejected with `ERASECURE_ERR_REAL_DEVICE_PATH` before any I/O occurs.

### No Privilege Escalation
EraseCure does not attempt to gain elevated privileges.  Real device operations
(planned for future phases) will require the process to already be running as
root — EraseCure will check `getuid()` but will not use `setuid` or `sudo`.

### Audit Chain Integrity
Each audit record includes `SHA-256(record_fields + previous_hash)`.  Any
modification to a historical record breaks the chain and is detected by
`audit_log_validate_chain()`.

### Cryptographic Primitives
All cryptographic operations use OpenSSL EVP APIs.  No custom cryptographic
algorithm implementations are present.

### Memory Safety
The project compiles with AddressSanitizer and UndefinedBehaviorSanitizer in
Debug builds.  All `malloc()` return values are checked.  Read/write lengths
are validated before use.

---

## Out of Scope

The following are NOT considered vulnerabilities in the current phase:

- Failing to erase NAND cells on SSDs via logical block overwrite (this is a
  known and documented hardware limitation, not a software bug).
- Stub functions returning `NOT_IMPLEMENTED` (by design).
- Lack of root-privilege enforcement (enforcement will be added when real device
  operations are implemented).
