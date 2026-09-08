/**
 * @file cli.c
 * @brief Command-line interface for EraseCure.
 *
 * All sanitization logic is delegated to the core library.
 * The CLI only handles argument parsing and output formatting.
 */
#define _POSIX_C_SOURCE 200809L

#include "ui/cli.h"
#include "device/device.h"
#include "device/device_detect.h"
#include "device/device_info.h"
#include "sanitization/block_erase.h"
#include "sanitization/verification.h"
#include "sanitization/sanitizer.h"
#include "sanitization/crypto_erase.h"
#include "audit/audit.h"
#include "audit/audit_log.h"
#include "common/constants.h"
#include "common/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ─── Banner helpers ─────────────────────────────────────────── */

static void print_banner(void)
{
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║  EraseCure v%-5s  —  Secure Data Sanitization  ║\n",
           ERASECURE_APP_VERSION);
    printf("╚══════════════════════════════════════════════════╝\n\n");
}

static void print_test_mode_warning(void)
{
    printf("┌─────────────────────────────────────────────────┐\n");
    printf("│  [TEST MODE]  Operating on disk image file only │\n");
    printf("│  No physical devices will be modified.          │\n");
    printf("└─────────────────────────────────────────────────┘\n\n");
}

void cli_print_usage(void)
{
    printf("Usage: erasecure <command> [options]\n\n");
    printf("Commands:\n");
    printf("  --list-devices\n");
    printf("        List all detected storage devices.\n\n");
    printf("  --info <device-path>\n");
    printf("        Show detailed information about a device.\n");
    printf("        Example: erasecure --info /dev/sda\n\n");
    printf("  --test-image <file> --block-erase <pattern>\n");
    printf("        Erase a disk image file with the specified pattern.\n");
    printf("        Pattern: zero | one | random\n");
    printf("        Options:\n");
    printf("          --passes <N>         Number of overwrite passes (default 1)\n");
    printf("          --block-size <N>     I/O chunk size in bytes (default 1MiB)\n");
    printf("          --verify             Verify after erase\n");
    printf("          --verify-full        Full readback verification\n");
    printf("        Example: erasecure --test-image test.img --block-erase zero --passes 3 --verify\n\n");
    printf("  --verify-image <file> --pattern <zero|one>\n");
    printf("        Verify that an image file contains the expected pattern.\n\n");
    printf("  --help\n");
    printf("        Show this help message.\n\n");
    printf("Safety:\n");
    printf("  Real device operations are NOT implemented in this version.\n");
    printf("  All destructive commands require --test-image (file path).\n\n");
}

/* ─── Sub-command implementations ────────────────────────────── */

static int cmd_list_devices(void)
{
    printf("Scanning storage devices via /sys/block...\n\n");

    StorageDevice devices[ERASECURE_MAX_DEVICES];
    size_t found = 0;

    ErasecureError err = device_scan(devices, ERASECURE_MAX_DEVICES, &found);
    if (err != ERASECURE_OK) {
        fprintf(stderr, "Error: device_scan failed: %s\n",
                erasecure_strerror(err));
        fprintf(stderr, "       (Are you running on Linux with /sys/block access?)\n");
        return 1;
    }

    if (found == 0) {
        printf("No storage devices found (or /sys/block not accessible).\n");
        return 0;
    }

    printf("Found %zu device(s):\n\n", found);
    for (size_t i = 0; i < found; ++i) {
        printf("Device #%zu\n", i + 1);
        printf("─────────────────────────────────────\n");
        device_print_info(&devices[i]);
        printf("\n");
    }
    return 0;
}

static int cmd_device_info(const char *path)
{
    if (!path) {
        fprintf(stderr, "Error: --info requires a device path.\n");
        return 1;
    }

    StorageDevice dev;
    ErasecureError err = device_get_info(path, &dev);
    if (err != ERASECURE_OK) {
        fprintf(stderr, "Error: device_get_info('%s') failed: %s\n",
                path, erasecure_strerror(err));
        return 1;
    }

    printf("Device Information\n");
    printf("──────────────────────────────────────\n");
    device_print_info(&dev);
    printf("\n");
    return 0;
}

static int cmd_block_erase_image(const char *image_path,
                                 const char *pattern_str,
                                 uint32_t    passes,
                                 size_t      block_size,
                                 VerifyMode  verify_mode)
{
    print_test_mode_warning();

    /* Parse pattern */
    ErasePattern pattern;
    if (strcmp(pattern_str, "zero") == 0) {
        pattern = ERASE_PATTERN_ZERO;
    } else if (strcmp(pattern_str, "one") == 0) {
        pattern = ERASE_PATTERN_ONE;
    } else if (strcmp(pattern_str, "random") == 0) {
        pattern = ERASE_PATTERN_RANDOM;
    } else {
        fprintf(stderr, "Error: unknown pattern '%s'. Use: zero | one | random\n",
                pattern_str);
        return 1;
    }

    /* Build options */
    BlockEraseOptions opts;
    block_erase_options_init(&opts);
    opts.pattern     = pattern;
    opts.passes      = (passes > 0) ? passes : 1U;
    opts.block_size  = (block_size > 0) ? block_size : ERASECURE_DEFAULT_BLOCK_SIZE;
    opts.verify_mode = verify_mode;

    /* Progress callback */
    opts.progress_cb = NULL;  /* CLI: simple non-interactive output */

    printf("Starting block erase on image: %s\n", image_path);
    printf("  Pattern    : %s\n", erase_pattern_str(pattern));
    printf("  Passes     : %u\n", opts.passes);
    printf("  Block size : %zu bytes\n", opts.block_size);
    printf("  Verify     : %s\n\n",
           verify_mode == VERIFY_NONE   ? "none" :
           verify_mode == VERIFY_SAMPLE ? "sampled" : "full");

    BlockEraseResult result;
    ErasecureError err = block_erase_image(image_path, &opts, &result);

    if (err == ERASECURE_ERR_REAL_DEVICE_PATH) {
        fprintf(stderr, "\n[SAFETY BLOCK] %s\n", result.error_message);
        fprintf(stderr, "Use --test-image with a regular file, not a block device.\n");
        return 2;
    }

    if (err != ERASECURE_OK) {
        fprintf(stderr, "Error: block erase failed: %s\n", result.error_message);
        return 1;
    }

    printf("Erase complete.\n");
    printf("  Bytes written : %llu\n",  (unsigned long long)result.bytes_written);
    printf("  Passes done   : %u\n",    result.passes_completed);
    printf("  Duration      : %.3f s\n\n", result.duration_seconds);

    /* Run verification if requested */
    if (verify_mode != VERIFY_NONE && pattern != ERASE_PATTERN_RANDOM) {
        printf("Running verification...\n");
        VerificationResult vr;
        ErasecureError ve = verify_image_pattern(image_path, pattern,
                                                  opts.block_size, verify_mode, &vr);
        if (ve != ERASECURE_OK && ve != ERASECURE_ERR_PATTERN_MISMATCH) {
            fprintf(stderr, "Verification error: %s\n", erasecure_strerror(ve));
        } else {
            printf("  Scope          : %s\n",  verification_scope_str(vr.scope));
            printf("  Blocks checked : %llu\n", (unsigned long long)vr.blocks_checked);
            printf("  Blocks failed  : %llu\n", (unsigned long long)vr.blocks_failed);
            printf("  Result         : %s\n",
                   vr.verification_passed ? "PASS" : "FAIL");
            printf("\n  Note: %s\n", vr.confidence_note);
        }
    } else if (verify_mode != VERIFY_NONE && pattern == ERASE_PATTERN_RANDOM) {
        printf("Note: Random pattern verification is not possible (non-deterministic).\n");
    }

    printf("\nAudit record (example — not written to DB in this demo):\n");
    printf("  Operation : block_erase_image\n");
    printf("  Image     : %s\n", image_path);
    printf("  Pattern   : %s\n", erase_pattern_str(pattern));
    printf("  Version   : %s\n", ERASECURE_APP_VERSION);

    return 0;
}

static int cmd_verify_image(const char *image_path, const char *pattern_str)
{
    print_test_mode_warning();

    ErasePattern pattern;
    if (strcmp(pattern_str, "zero") == 0) {
        pattern = ERASE_PATTERN_ZERO;
    } else if (strcmp(pattern_str, "one") == 0) {
        pattern = ERASE_PATTERN_ONE;
    } else {
        fprintf(stderr, "Error: verify supports only 'zero' or 'one' patterns.\n");
        return 1;
    }

    printf("Verifying image: %s (expected pattern: %s)\n\n",
           image_path, erase_pattern_str(pattern));

    VerificationResult vr;
    ErasecureError err = verify_image_pattern(image_path, pattern,
                                              ERASECURE_DEFAULT_BLOCK_SIZE,
                                              VERIFY_SAMPLE, &vr);
    if (err != ERASECURE_OK && err != ERASECURE_ERR_PATTERN_MISMATCH) {
        fprintf(stderr, "Error: %s\n", erasecure_strerror(err));
        return 1;
    }

    printf("  Scope          : %s\n",  verification_scope_str(vr.scope));
    printf("  Blocks total   : %llu\n", (unsigned long long)vr.blocks_total);
    printf("  Blocks checked : %llu\n", (unsigned long long)vr.blocks_checked);
    printf("  Blocks failed  : %llu\n", (unsigned long long)vr.blocks_failed);
    printf("  Result         : %s\n",   vr.verification_passed ? "PASS" : "FAIL");
    printf("\n  Note: %s\n", vr.confidence_note);

    return vr.verification_passed ? 0 : 1;
}

/* ─── Main dispatcher ────────────────────────────────────────── */

int cli_run(int argc, char *argv[])
{
    print_banner();

    if (argc < 2) {
        cli_print_usage();
        return 0;
    }

    /* ── --help ── */
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        cli_print_usage();
        return 0;
    }

    /* ── --list-devices ── */
    if (strcmp(argv[1], "--list-devices") == 0) {
        return cmd_list_devices();
    }

    /* ── --info <path> ── */
    if (strcmp(argv[1], "--info") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: --info requires a device path.\n");
            return 1;
        }
        return cmd_device_info(argv[2]);
    }

    /* ── --test-image <file> --block-erase <pattern> [options] ── */
    if (strcmp(argv[1], "--test-image") == 0) {
        if (argc < 5) {
            fprintf(stderr, "Error: --test-image requires a file and --block-erase <pattern>.\n");
            cli_print_usage();
            return 1;
        }
        const char *image_path = argv[2];

        /* Find --block-erase */
        const char *pattern_str = NULL;
        uint32_t    passes      = 1;
        size_t      block_size  = 0;
        VerifyMode  verify_mode = VERIFY_NONE;

        for (int i = 3; i < argc; ++i) {
            if (strcmp(argv[i], "--block-erase") == 0 && i + 1 < argc) {
                pattern_str = argv[++i];
            } else if (strcmp(argv[i], "--passes") == 0 && i + 1 < argc) {
                long p = strtol(argv[++i], NULL, 10);
                passes = (p > 0 && p <= (long)ERASECURE_MAX_PASSES)
                         ? (uint32_t)p : 1U;
            } else if (strcmp(argv[i], "--block-size") == 0 && i + 1 < argc) {
                long bs = strtol(argv[++i], NULL, 10);
                block_size = (bs > 0) ? (size_t)bs : 0;
            } else if (strcmp(argv[i], "--verify") == 0) {
                verify_mode = VERIFY_SAMPLE;
            } else if (strcmp(argv[i], "--verify-full") == 0) {
                verify_mode = VERIFY_FULL;
            }
        }

        if (!pattern_str) {
            fprintf(stderr, "Error: missing --block-erase <pattern>.\n");
            return 1;
        }
        return cmd_block_erase_image(image_path, pattern_str, passes,
                                     block_size, verify_mode);
    }

    /* ── --verify-image <file> --pattern <zero|one> ── */
    if (strcmp(argv[1], "--verify-image") == 0) {
        if (argc < 5) {
            fprintf(stderr, "Error: --verify-image requires a file and --pattern <zero|one>.\n");
            return 1;
        }
        const char *image_path  = argv[2];
        const char *pattern_str = NULL;
        for (int i = 3; i < argc; ++i) {
            if (strcmp(argv[i], "--pattern") == 0 && i + 1 < argc) {
                pattern_str = argv[++i];
            }
        }
        if (!pattern_str) {
            fprintf(stderr, "Error: missing --pattern <zero|one>.\n");
            return 1;
        }
        return cmd_verify_image(image_path, pattern_str);
    }

    fprintf(stderr, "Unknown command: %s\n\n", argv[1]);
    cli_print_usage();
    return 1;
}
