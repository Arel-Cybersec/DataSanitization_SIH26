/**
 * @file audit_log.h
 * @brief Audit log file and SQLite3 persistence layer.
 */
#ifndef ERASECURE_AUDIT_LOG_H
#define ERASECURE_AUDIT_LOG_H

#include "audit/audit.h"
#include "common/error.h"
#include <stddef.h>

/* Opaque database handle */
typedef struct AuditDb AuditDb;

/* ─── Chain validation result ────────────────────────────────── */
typedef enum {
    AUDIT_CHAIN_VALID    = 0,
    AUDIT_CHAIN_TAMPERED = 1,
    AUDIT_CHAIN_EMPTY    = 2,
    AUDIT_CHAIN_ERROR    = 3,
} AuditChainStatus;

/* ═══════════════════════════════════════════════════════════════
 * File-based audit log (JSON lines)
 * ═══════════════════════════════════════════════════════════════ */

/**
 * @brief Append an AuditRecord to a JSON-lines log file.
 *
 * Creates the file and its parent directory if they do not exist.
 *
 * @param log_path  Path to the log file.
 * @param record    Record to write.
 * @return          ERASECURE_OK on success.
 */
ErasecureError audit_log_append_file(const char *log_path,
                                     const AuditRecord *record);

/**
 * @brief Validate the tamper-evident chain in a JSON-lines log file.
 *
 * Re-derives each record's hash and checks it against the stored value
 * and the previous record's hash.
 *
 * @param log_path  Path to the log file.
 * @param status    Output: chain status.
 * @return          ERASECURE_OK if validation ran (check *status),
 *                  ERASECURE_ERR_* if the file could not be read.
 */
ErasecureError audit_log_validate_chain(const char *log_path,
                                        AuditChainStatus *status);

/* ═══════════════════════════════════════════════════════════════
 * SQLite3 persistence layer
 * ═══════════════════════════════════════════════════════════════ */

/**
 * @brief Open (or create) the SQLite3 audit database.
 *
 * @param db_path  Path to the .db file.
 * @param db       Output: opaque handle.
 * @return         ERASECURE_OK on success.
 */
ErasecureError audit_db_open(const char *db_path, AuditDb **db);

/**
 * @brief Create the audit schema if it does not exist.
 */
ErasecureError audit_db_init_schema(AuditDb *db);

/**
 * @brief Insert an AuditRecord into the database.
 */
ErasecureError audit_db_insert(AuditDb *db, const AuditRecord *record);

/**
 * @brief Close the database and free the handle.
 */
void audit_db_close(AuditDb *db);

/**
 * @brief Return the last SQLite error message for debugging.
 */
const char *audit_db_errmsg(AuditDb *db);

#endif /* ERASECURE_AUDIT_LOG_H */
