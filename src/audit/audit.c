/**
 * @file audit.c
 * @brief Audit record initialisation, serialisation, and hash chaining.
 */
#define _POSIX_C_SOURCE 200809L

#include "audit/audit.h"
#include "crypto/hash.h"
#include "common/constants.h"
#include "common/error.h"
#include "device/device.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

/* ─── Helpers ────────────────────────────────────────────────── */

static void timestamp_to_iso8601(ErasecureTimestamp ts, char *buf, size_t len)
{
    struct tm *tm_info = gmtime(&ts);
    if (tm_info) {
        strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", tm_info);
    } else {
        snprintf(buf, len, "0000-00-00T00:00:00Z");
    }
}

/* ─── Public API ─────────────────────────────────────────────── */

void audit_record_init(AuditRecord *record)
{
    if (!record) return;
    memset(record, 0, sizeof(*record));
    snprintf(record->app_version, sizeof(record->app_version),
             "%s", ERASECURE_APP_VERSION);
}

ErasecureError audit_record_finalize(AuditRecord *record,
                                     const char *prev_hash)
{
    if (!record) return ERASECURE_ERR_NULL_PTR;

    /* Store previous hash */
    if (prev_hash && *prev_hash) {
        snprintf(record->previous_record_hash,
                 sizeof(record->previous_record_hash), "%s", prev_hash);
    } else {
        memset(record->previous_record_hash, 0,
               sizeof(record->previous_record_hash));
    }

    /* Serialise the record fields into a canonical string for hashing.
     * We include the previous hash to create a chain. */
    char serial_buf[4096];
    int n = snprintf(serial_buf, sizeof(serial_buf),
        "case_id=%s|op_id=%s|seq=%llu|dev_path=%s|model=%s|serial=%s"
        "|capacity=%llu|dev_type=%d|transport=%d|method=%d|pattern=%d"
        "|passes=%u|start=%lld|end=%lld|sanitize_result=%d"
        "|verify_result=%d|verify_passed=%d|pre_hash=%s|post_hash=%s"
        "|app_version=%s|prev_hash=%s",
        record->case_id,
        record->operation_id,
        (unsigned long long)record->sequence_number,
        record->device_path,
        record->device_model,
        record->device_serial,
        (unsigned long long)record->device_capacity_bytes,
        (int)record->device_type,
        (int)record->transport_type,
        (int)record->method,
        (int)record->pattern,
        record->passes,
        (long long)record->start_time,
        (long long)record->end_time,
        (int)record->sanitization_result,
        (int)record->verification_result_code,
        record->verification_passed ? 1 : 0,
        record->pre_hash_sha256,
        record->post_hash_sha256,
        record->app_version,
        record->previous_record_hash);

    if (n < 0 || (size_t)n >= sizeof(serial_buf)) {
        return ERASECURE_ERR_OVERFLOW;
    }

    /* Compute SHA-256 of the canonical string */
    uint8_t digest[ERASECURE_SHA256_DIGEST_LEN];
    ErasecureError err = hash_sha256_buffer(
        (const uint8_t *)serial_buf, (size_t)n, digest);
    if (err != ERASECURE_OK) return err;

    hash_digest_to_hex(digest, ERASECURE_SHA256_DIGEST_LEN,
                       record->this_record_hash);
    return ERASECURE_OK;
}

int audit_record_to_json(const AuditRecord *record, char *buf, size_t buf_len)
{
    if (!record || !buf || buf_len == 0) return -1;

    char start_str[32], end_str[32];
    timestamp_to_iso8601(record->start_time, start_str, sizeof(start_str));
    timestamp_to_iso8601(record->end_time,   end_str,   sizeof(end_str));

    int n = snprintf(buf, buf_len,
        "{"
        "\"case_id\":\"%s\","
        "\"operation_id\":\"%s\","
        "\"sequence_number\":%llu,"
        "\"device_id\":\"%s\","
        "\"device_path\":\"%s\","
        "\"device_model\":\"%s\","
        "\"device_serial\":\"%s\","
        "\"device_capacity_bytes\":%llu,"
        "\"device_type\":%d,"
        "\"transport_type\":%d,"
        "\"method\":%d,"
        "\"pattern\":%d,"
        "\"passes\":%u,"
        "\"app_version\":\"%s\","
        "\"start_time\":\"%s\","
        "\"end_time\":\"%s\","
        "\"sanitization_result\":%d,"
        "\"verification_result_code\":%d,"
        "\"verification_passed\":%s,"
        "\"pre_hash_sha256\":\"%s\","
        "\"post_hash_sha256\":\"%s\","
        "\"previous_record_hash\":\"%s\","
        "\"this_record_hash\":\"%s\","
        "\"notes\":\"%s\""
        "}",
        record->case_id,
        record->operation_id,
        (unsigned long long)record->sequence_number,
        record->device_id,
        record->device_path,
        record->device_model,
        record->device_serial,
        (unsigned long long)record->device_capacity_bytes,
        (int)record->device_type,
        (int)record->transport_type,
        (int)record->method,
        (int)record->pattern,
        record->passes,
        record->app_version,
        start_str,
        end_str,
        (int)record->sanitization_result,
        (int)record->verification_result_code,
        record->verification_passed ? "true" : "false",
        record->pre_hash_sha256,
        record->post_hash_sha256,
        record->previous_record_hash,
        record->this_record_hash,
        record->notes);

    return n;
}
