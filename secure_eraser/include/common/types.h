/**
 * @file types.h
 * @brief Fundamental type definitions for EraseCure.
 *
 * All modules include this file for common base types.
 */
#ifndef ERASECURE_TYPES_H
#define ERASECURE_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

/* ─── Byte alias ─────────────────────────────────────────────── */
typedef uint8_t  byte_t;

/* ─── SHA-256 / SHA-512 digest sizes ─────────────────────────── */
#define ERASECURE_SHA256_DIGEST_LEN  32U
#define ERASECURE_SHA512_DIGEST_LEN  64U

/* Hex-string representations (digest * 2 + NUL) */
#define ERASECURE_SHA256_HEX_LEN    (ERASECURE_SHA256_DIGEST_LEN * 2U + 1U)
#define ERASECURE_SHA512_HEX_LEN    (ERASECURE_SHA512_DIGEST_LEN * 2U + 1U)

/* ─── UUID-style operation/case identifiers ──────────────────── */
#define ERASECURE_ID_LEN  37U   /* "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\0" */
typedef char ErasecureId[ERASECURE_ID_LEN];

/* ─── Timestamps ─────────────────────────────────────────────── */
typedef time_t ErasecureTimestamp;

/* ─── Forward declarations of major structs ──────────────────── */
typedef struct StorageDevice        StorageDevice;
typedef struct SanitizationOptions  SanitizationOptions;
typedef struct SanitizationProgress SanitizationProgress;
typedef struct SanitizationResult   SanitizationResult;
typedef struct VerificationResult   VerificationResult;
typedef struct AuditRecord          AuditRecord;

#endif /* ERASECURE_TYPES_H */
