/**
 * @file audit.h
 * @brief Audit record structure and tamper-evident hash chain.
 */
#ifndef ERASECURE_AUDIT_H
#define ERASECURE_AUDIT_H

#include "common/types.h"
#include "common/constants.h"
#include "common/error.h"
#include "device/device.h"
#include "sanitization/block_erase.h"
#include "sanitization/crypto_erase.h"
#include "sanitization/verification.h"
#include <time.h>
#include <stdint.h>

/* ─── Audit record ───────────────────────────────────────────── */
struct AuditRecord {
    /* Case and operation identity */
    char               case_id[ERASECURE_MAX_CASE_ID_LEN];
    char               operation_id[ERASECURE_MAX_OP_ID_LEN];
    uint64_t           sequence_number;

    /* Device identity */
    char               device_id[ERASECURE_MAX_PATH_LEN];
    char               device_path[ERASECURE_MAX_PATH_LEN];
    char               device_model[ERASECURE_MAX_MODEL_LEN];
    char               device_serial[ERASECURE_MAX_SERIAL_LEN];
    uint64_t           device_capacity_bytes;
    DeviceType         device_type;
    TransportType      transport_type;

    /* Sanitization details */
    SanitizationMethod method;
    ErasePattern       pattern;        /* valid if method == BLOCK_ERASE */
    uint32_t           passes;
    char               app_version[32];

    /* Timing */
    ErasecureTimestamp start_time;
    ErasecureTimestamp end_time;

    /* Outcome */
    ErasecureError     sanitization_result;
    ErasecureError     verification_result_code;
    bool               verification_passed;

    /* Hashes of the image/device (pre/post, if applicable) */
    char               pre_hash_sha256[ERASECURE_SHA256_HEX_LEN];
    char               post_hash_sha256[ERASECURE_SHA256_HEX_LEN];

    /* Tamper-evident chain */
    char               previous_record_hash[ERASECURE_SHA256_HEX_LEN];
    char               this_record_hash[ERASECURE_SHA256_HEX_LEN];

    /* Human-readable notes */
    char               notes[512];
};

/**
 * @brief Initialise an AuditRecord to safe defaults.
 */
void audit_record_init(AuditRecord *record);

/**
 * @brief Compute and set this_record_hash from the record's fields.
 *
 * The hash is: SHA256( serialized_record_fields + previous_record_hash )
 * This links records into a tamper-evident chain.
 *
 * @param record        Record to finalise (modifies this_record_hash).
 * @param prev_hash     Hex hash of the previous record; empty string if first.
 * @return              ERASECURE_OK on success.
 */
ErasecureError audit_record_finalize(AuditRecord *record,
                                     const char *prev_hash);

/**
 * @brief Serialise an AuditRecord to a JSON string.
 *
 * @param record   Record to serialise.
 * @param buf      Output buffer.
 * @param buf_len  Size of output buffer.
 * @return         Number of bytes written (excluding NUL), or -1 on error.
 */
int audit_record_to_json(const AuditRecord *record, char *buf, size_t buf_len);

#endif /* ERASECURE_AUDIT_H */
