/**
 * @file file_eraser_tests.c
 * @brief Unit tests for File & Folder Eraser module (Module 2).
 */
#define _POSIX_C_SOURCE 200809L

#include "file_eraser/file_eraser.h"
#include "file_eraser/folder_eraser.h"
#include "file_eraser/metadata_eraser.h"
#include "file_eraser/file_verify.h"
#include "sanitization/block_erase.h"
#include "common/error.h"
#include "common/constants.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define TEST_ASSERT(cond, name) do { \
    g_tests_run++; \
    if (cond) { \
        g_tests_passed++; \
        printf("  [PASS] %s\n", name); \
    } else { \
        printf("  [FAIL] %s\n", name); \
    } \
} while (0)

static char *create_temp_test_file(const char *content, size_t len)
{
    static char template_path[256];
    snprintf(template_path, sizeof(template_path), "/tmp/ec_test_file_XXXXXX");
    int fd = mkstemp(template_path);
    if (fd < 0) {
        /* Fallback for environments without /tmp */
        snprintf(template_path, sizeof(template_path), "ec_tmp_test_%u.dat", (unsigned)rand());
        FILE *f = fopen(template_path, "wb");
        if (f) {
            if (content && len > 0) fwrite(content, 1, len, f);
            fclose(f);
            return template_path;
        }
        return NULL;
    }
    if (content && len > 0) {
        ssize_t w = write(fd, content, len);
        (void)w;
    }
    close(fd);
    return template_path;
}

int main(void)
{
    printf("=== Running Real File Eraser Unit Tests ===\n");

    /* Test 1: Options init */
    FileEraseOptions fopts;
    file_erase_options_init(&fopts);
    TEST_ASSERT(fopts.pattern == ERASE_PATTERN_ZERO && fopts.passes == 1,
                "file_erase_options_init sets default pattern ZERO and passes 1");

    /* Test 2: File erase zero pattern */
    const char *data = "TOP SECRET EVIDENCE DATA TO DESTROY 1234567890";
    char *p1 = create_temp_test_file(data, strlen(data));
    if (p1) {
        FileEraseResult res;
        fopts.remove_file = false;
        fopts.verify_after = true;
        ErasecureError err = file_erase(p1, &fopts, &res);
        TEST_ASSERT(err == ERASECURE_OK && res.passes_completed == 1,
                    "file_erase zero pattern completes successfully");
        unlink(p1);
    }

    /* Test 3: File erase one pattern (0xFF) */
    char *p2 = create_temp_test_file(data, strlen(data));
    if (p2) {
        FileEraseResult res;
        fopts.pattern = ERASE_PATTERN_ONE;
        fopts.remove_file = false;
        fopts.verify_after = true;
        ErasecureError err = file_erase(p2, &fopts, &res);
        TEST_ASSERT(err == ERASECURE_OK && res.verification_passed,
                    "file_erase one pattern (0xFF) passes verification");
        unlink(p2);
    }

    /* Test 4: File erase random pattern */
    char *p3 = create_temp_test_file(data, strlen(data));
    if (p3) {
        FileEraseResult res;
        fopts.pattern = ERASE_PATTERN_RANDOM;
        fopts.remove_file = false;
        fopts.verify_after = false;
        ErasecureError err = file_erase(p3, &fopts, &res);
        TEST_ASSERT(err == ERASECURE_OK && res.bytes_written >= strlen(data),
                    "file_erase random pattern completes with bytes written");
        unlink(p3);
    }

    /* Test 5: File erase with remove_file (unlinks file) */
    char *p4 = create_temp_test_file(data, strlen(data));
    if (p4) {
        FileEraseResult res;
        fopts.pattern = ERASE_PATTERN_ZERO;
        fopts.remove_file = true;
        ErasecureError err = file_erase(p4, &fopts, &res);
        struct stat st;
        int stat_res = stat(p4, &st);
        TEST_ASSERT(err == ERASECURE_OK && stat_res != 0 && res.file_removed,
                    "file_erase with remove_file unlinks the file from filesystem");
    }

    /* Test 6: Safety check rejecting dangerous root path */
    {
        FileEraseResult res;
        ErasecureError err = file_erase("/", &fopts, &res);
        TEST_ASSERT(err == ERASECURE_ERR_DANGEROUS_PATH || err == ERASECURE_ERR_INVALID_ARG,
                    "file_erase rejects root directory '/' for safety");
    }

    /* Test 7: Safety check rejecting /etc */
    {
        FileEraseResult res;
        ErasecureError err = file_erase("/etc", &fopts, &res);
        TEST_ASSERT(err == ERASECURE_ERR_DANGEROUS_PATH || err == ERASECURE_ERR_INVALID_ARG,
                    "file_erase rejects system directory '/etc' for safety");
    }

    /* Test 8: Metadata erase */
    char *p5 = create_temp_test_file(data, strlen(data));
    if (p5) {
        MetadataEraseResult mres;
        ErasecureError err = metadata_erase(p5, &mres);
        TEST_ASSERT(err == ERASECURE_OK && mres.limitation_note[0] != '\0',
                    "metadata_erase executes and sets honest forensic limitation note");
        unlink(p5);
    }

    /* Test 9: File verify detects pattern */
    char *p6 = create_temp_test_file("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16);
    if (p6) {
        FileVerifyResult vres;
        ErasecureError err = file_verify_pattern(p6, ERASE_PATTERN_ZERO, &vres);
        TEST_ASSERT(err == ERASECURE_OK && vres.passed && vres.bytes_mismatched == 0,
                    "file_verify_pattern confirms all-zero pattern matches");
        unlink(p6);
    }

    /* Test 10: Folder erase options init */
    FolderEraseOptions fld_opts;
    folder_erase_options_init(&fld_opts);
    TEST_ASSERT(fld_opts.remove_dirs == true && fld_opts.max_depth > 0,
                "folder_erase_options_init sets safe defaults");

    printf("File Eraser Tests Summary: %d/%d passed.\n", g_tests_passed, g_tests_run);
    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
