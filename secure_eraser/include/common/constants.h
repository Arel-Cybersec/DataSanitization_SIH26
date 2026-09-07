/**
 * @file constants.h
 * @brief Project-wide constants for EraseCure.
 */
#ifndef ERASECURE_CONSTANTS_H
#define ERASECURE_CONSTANTS_H

/* ─── Application identity ───────────────────────────────────── */
#define ERASECURE_APP_NAME       "EraseCure"
#define ERASECURE_APP_VERSION    "0.1.0-dev"
#define ERASECURE_APP_VENDOR     "EraseCure Project"

/* ─── Device enumeration limits ─────────────────────────────── */
#define ERASECURE_MAX_DEVICES         64U
#define ERASECURE_MAX_PATH_LEN       256U
#define ERASECURE_MAX_MODEL_LEN       64U
#define ERASECURE_MAX_SERIAL_LEN      64U
#define ERASECURE_MAX_SYSFS_PATH_LEN 512U

/* ─── Block erase defaults ───────────────────────────────────── */
#define ERASECURE_DEFAULT_BLOCK_SIZE  (1U * 1024U * 1024U)   /* 1 MiB */
#define ERASECURE_MIN_BLOCK_SIZE      512U
#define ERASECURE_MAX_BLOCK_SIZE      (64U * 1024U * 1024U)  /* 64 MiB */
#define ERASECURE_DEFAULT_PASSES      1U
#define ERASECURE_MAX_PASSES          35U   /* DoD 5220.22-M max */

/* ─── Verification sampling ──────────────────────────────────── */
#define ERASECURE_VERIFY_SAMPLE_BLOCKS  16U  /* blocks sampled for spot check */

/* ─── Audit & DB ─────────────────────────────────────────────── */
#define ERASECURE_AUDIT_LOG_DIR      "data/logs"
#define ERASECURE_REPORT_DIR         "data/reports"
#define ERASECURE_DB_FILENAME        "data/erasecure_audit.db"
#define ERASECURE_MAX_CASE_ID_LEN    64U
#define ERASECURE_MAX_OP_ID_LEN      64U

/* ─── Safety: prefixes that identify physical block devices ──── */
/* These are checked to prevent test-mode functions from touching
 * real devices.  This list is not exhaustive on all Linux systems
 * but covers the most common block-device prefixes.              */
#define ERASECURE_BLOCKDEV_PREFIXES \
    "/dev/sd",  \
    "/dev/hd",  \
    "/dev/nvme",\
    "/dev/vd",  \
    "/dev/xvd", \
    "/dev/mmcblk", \
    "/dev/fd",  \
    "/dev/sr",  \
    "/dev/scd", \
    NULL

/* ─── sysfs paths ────────────────────────────────────────────── */
#define SYSFS_BLOCK_DIR              "/sys/block"
#define SYSFS_ROTATIONAL_FMT         "/sys/block/%s/queue/rotational"
#define SYSFS_REMOVABLE_FMT          "/sys/block/%s/removable"
#define SYSFS_SIZE_FMT               "/sys/block/%s/size"
#define SYSFS_MODEL_FMT              "/sys/block/%s/device/model"
#define SYSFS_SERIAL_FMT             "/sys/block/%s/device/serial"
#define SYSFS_LOGICAL_BS_FMT         "/sys/block/%s/queue/logical_block_size"
#define SYSFS_PHYSICAL_BS_FMT        "/sys/block/%s/queue/physical_block_size"
#define SYSFS_RO_FMT                 "/sys/block/%s/ro"
#define SYSFS_SUBSYSTEM_FMT          "/sys/block/%s/device/subsystem"

/* ─── Mount detection ────────────────────────────────────────── */
#define ERASECURE_PROC_MOUNTS        "/proc/mounts"

/* ─── File/folder eraser ─────────────────────────────────────── */
#define ERASECURE_MAX_ERASE_DEPTH    128U     /* max recursion depth */
#define ERASECURE_DANGEROUS_PATHS                                       \
    "/", "/boot", "/etc", "/usr", "/bin", "/sbin", "/lib",              \
    "/lib64", "/proc", "/sys", "/dev", "/run", "/var", NULL

/* ─── Recovery / carving engine ──────────────────────────────── */
#define ERASECURE_DEFAULT_CARVE_BLOCK_SIZE  512U
#define ERASECURE_MAX_SIGNATURES            256U
#define ERASECURE_MAX_FILE_TYPES            64U
#define ERASECURE_MAX_CANDIDATES            4096U
#define ERASECURE_CONFIDENCE_MIN            0U
#define ERASECURE_CONFIDENCE_MAX            100U
#define ERASECURE_UUID_LEN                  37U

/* ─── Worker pool ────────────────────────────────────────────── */
#define ERASECURE_DEFAULT_WORKER_COUNT      4U
#define ERASECURE_MAX_WORKER_COUNT          32U

/* ─── Checkpointing ──────────────────────────────────────────── */
#define ERASECURE_CHECKPOINT_MAGIC          0x45435043U  /* "ECPC" */
#define ERASECURE_CHECKPOINT_VERSION        1U
#define ERASECURE_CHECKPOINT_INTERVAL_SEC   30U

/* ─── Recovery output dirs ───────────────────────────────────── */
#define ERASECURE_OUTPUT_VALIDATED    "VALIDATED"
#define ERASECURE_OUTPUT_PROMISING    "PROMISING"
#define ERASECURE_OUTPUT_INPROGRESS   "INPROGRESS"

#endif /* ERASECURE_CONSTANTS_H */
