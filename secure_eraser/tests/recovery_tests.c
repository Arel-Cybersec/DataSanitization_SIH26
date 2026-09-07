/**
 * @file recovery_tests.c
 * @brief Real unit tests for Forensic File Carving and Recovery Engine (Module 3).
 */
#define _POSIX_C_SOURCE 200809L

#include "recovery/file_mirror.h"
#include "recovery/blockmap.h"
#include "recovery/blockvector.h"
#include "recovery/block_state.h"
#include "recovery/carve_state.h"
#include "recovery/discovery.h"
#include "recovery/file_type_registry.h"
#include "recovery/validator.h"
#include "recovery/promising_queue.h"
#include "recovery/reassembly.h"
#include "recovery/recovery_engine.h"
#include "recovery/checkpoint.h"
#include "recovery/recovery_output.h"
#include "formats/all_formats.h"
#include "testing/test_image_gen.h"
#include "common/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

int main(void)
{
    printf("=== Running Real Forensic Recovery Engine Unit Tests ===\n");

    /* Test 1: Blockvector create, append, get, remove_last, restore */
    {
        Blockvector bv;
        ErasecureError err = blockvector_create(&bv, 8);
        TEST_ASSERT(err == ERASECURE_OK && blockvector_length(&bv) == 0,
                    "blockvector_create initializes empty vector");

        blockvector_append(&bv, 0, 100);
        blockvector_append(&bv, 1, 101);
        blockvector_append(&bv, 2, 102);
        TEST_ASSERT(blockvector_length(&bv) == 3,
                    "blockvector_append adds slots correctly");

        const BvSlot *slot = blockvector_get(&bv, 1);
        TEST_ASSERT(slot && slot->actual_block == 101,
                    "blockvector_get retrieves slot data");

        blockvector_remove_last(&bv);
        TEST_ASSERT(blockvector_length(&bv) == 2,
                    "blockvector_remove_last pops last slot");

        blockvector_restore(&bv, 1);
        TEST_ASSERT(blockvector_length(&bv) == 1,
                    "blockvector_restore trims to target length for backtracking");

        blockvector_free(&bv);
    }

    /* Test 2: Blockmap create, reserve, release, shadow merge */
    {
        Blockmap bm;
        ErasecureError err = blockmap_create(&bm, 16);
        TEST_ASSERT(err == ERASECURE_OK, "blockmap_create initializes blockmap");

        blockmap_reserve(&bm, 5);
        blockmap_reserve(&bm, 5);
        TEST_ASSERT(blockmap_reservation_count(&bm, 5) == 2,
                    "blockmap_reserve tracks reservation count correctly");

        blockmap_release(&bm, 5);
        TEST_ASSERT(blockmap_reservation_count(&bm, 5) == 1,
                    "blockmap_release decrements reservation count");

        blockmap_shadow_set_covered(&bm, 3, true);
        blockmap_merge_shadow(&bm);
        TEST_ASSERT(blockmap_covered_count(&bm) == 1,
                    "blockmap_merge_shadow commits shadow updates to primary map");

        blockmap_destroy(&bm);
    }

    /* Test 3: CarveState and UUID generation */
    {
        CarveState cs;
        ErasecureError err = carve_state_create(&cs, "JPEG", 42);
        TEST_ASSERT(err == ERASECURE_OK && strlen(cs.uuid) == 36 && cs.start_block == 42,
                    "carve_state_create assigns valid UUID and start block");
        TEST_ASSERT(strcmp(candidate_status_str(cs.status), "NEW") == 0,
                    "candidate_status_str returns NEW for new candidate");
        carve_state_free(&cs);
    }

    /* Test 4: PromisingQueue enqueue, dequeue, size */
    {
        PromisingQueue pq;
        ErasecureError err = promising_queue_init(&pq, 16);
        TEST_ASSERT(err == ERASECURE_OK, "promising_queue_init succeeds");

        CarveState c1, c2;
        carve_state_create(&c1, "PNG", 10);
        carve_state_create(&c2, "JPEG", 20);
        c1.priority = 100;
        c2.priority = 50; /* higher priority (lower numerical value) */

        promising_queue_enqueue(&pq, &c1);
        promising_queue_enqueue(&pq, &c2);
        TEST_ASSERT(promising_queue_size(&pq) == 2, "promising_queue_size returns 2");

        CarveState *out = NULL;
        promising_queue_dequeue(&pq, &out);
        TEST_ASSERT(out != NULL, "promising_queue_dequeue retrieves entry");

        promising_queue_destroy(&pq);
        carve_state_free(&c1);
        carve_state_free(&c2);
    }

    /* Test 5: FileTypeRegistry and register_all_validators */
    {
        FileTypeRegistry reg;
        file_type_registry_init(&reg);
        file_type_registry_register_defaults(&reg);
        register_all_validators(&reg);

        const FileTypeDescriptor *jpg_desc = file_type_registry_find(&reg, "JPEG");
        const FileTypeDescriptor *png_desc = file_type_registry_find(&reg, "PNG");
        const FileTypeDescriptor *pdf_desc = file_type_registry_find(&reg, "PDF");
        const FileTypeDescriptor *zip_desc = file_type_registry_find(&reg, "ZIP");

        TEST_ASSERT(jpg_desc != NULL && png_desc != NULL && pdf_desc != NULL && zip_desc != NULL,
                    "file_type_registry registers all default types with validators");

        file_type_registry_destroy(&reg);
    }

    /* Test 6: JPEG Validator on synthetic data */
    {
        /* Minimal synthetic JPEG SOI (FF D8) + EOI (FF D9) */
        uint8_t synthetic_jpg[] = {
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10,
            'J', 'F', 'I', 'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00,
            0xFF, 0xD9
        };

        size_t parsed = 0;
        FileValidationResult res = jpeg_file_validator(synthetic_jpg, sizeof(synthetic_jpg), &parsed);
        TEST_ASSERT(res.outcome == FILE_VALIDATION_VALIDATES || res.outcome == FILE_VALIDATION_PROMISING,
                    "jpeg_file_validator validates synthetic JPEG with SOI and EOI");
    }

    /* Test 7: PNG Validator on synthetic data */
    {
        /* PNG header: 89 50 4E 47 0D 0A 1A 0A */
        uint8_t png_header[8] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
        size_t parsed = 0;
        FileValidationResult res = png_file_validator(png_header, sizeof(png_header), &parsed);
        TEST_ASSERT(res.outcome == FILE_VALIDATION_PROMISING,
                    "png_file_validator recognizes valid PNG magic as PROMISING");
    }

    /* Test 8: Synthetic Evidence Image Generation and FileMirror */
    {
        char img_path[] = "tmp_evidence_img_XXXXXX";
        int fd = mkstemp(img_path);
        if (fd >= 0) {
            close(fd);
            SyntheticEvidenceImage simg;
            ErasecureError err = test_image_gen_init(&simg, img_path, 512, 64);
            TEST_ASSERT(err == ERASECURE_OK, "test_image_gen_init succeeds");

            const char *test_content = "CARVING BENCHMARK EMBEDDED FILE CONTENT";
            GroundTruthRecord gt;
            test_image_gen_embed_file(&simg, "sample.txt", test_content, strlen(test_content),
                                      FRAG_PATTERN_CONTIGUOUS, &gt);

            test_image_gen_write(&simg);
            test_image_gen_destroy(&simg);

            /* Open via FileMirror */
            FileMirror fm;
            ErasecureError fm_err = file_mirror_open(&fm, img_path, 512);
            TEST_ASSERT(fm_err == ERASECURE_OK && fm.total_blocks == 64,
                        "file_mirror_open mounts synthetic evidence image");

            ErasecureError v_err = file_mirror_verify_integrity(&fm);
            TEST_ASSERT(v_err == ERASECURE_OK,
                        "file_mirror_verify_integrity matches initial evidence hash");

            file_mirror_close(&fm);
            unlink(img_path);
        }
    }

    /* Test 9: Reassembly options init */
    {
        ReassemblyOptions ropts;
        reassembly_options_init(&ropts);
        TEST_ASSERT(ropts.max_backtracks > 0 && ropts.galloping_step > 0,
                    "reassembly_options_init sets positive backtrack and galloping defaults");
    }

    /* Test 10: Recovery output initialization */
    {
        ErasecureError err = recovery_output_init("test_recovery_output");
        TEST_ASSERT(err == ERASECURE_OK,
                    "recovery_output_init creates output directories successfully");
    }

    printf("Forensic Recovery Engine Tests Summary: %d/%d passed.\n", g_tests_passed, g_tests_run);
    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
