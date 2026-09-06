/**
 * @file hash.c
 * @brief SHA-256 and SHA-512 implementation using OpenSSL EVP API.
 */
#include "crypto/hash.h"
#include "common/error.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* ─── Internal EVP helper ────────────────────────────────────── */

static ErasecureError evp_hash_buffer(const EVP_MD *md,
                                      const uint8_t *data, size_t data_len,
                                      uint8_t *digest, unsigned int *digest_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return ERASECURE_ERR_CRYPTO;

    ErasecureError ret = ERASECURE_OK;

    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
        ret = ERASECURE_ERR_HASH_FAILED;
        goto cleanup;
    }
    if (EVP_DigestUpdate(ctx, data, data_len) != 1) {
        ret = ERASECURE_ERR_HASH_FAILED;
        goto cleanup;
    }
    if (EVP_DigestFinal_ex(ctx, digest, digest_len) != 1) {
        ret = ERASECURE_ERR_HASH_FAILED;
        goto cleanup;
    }

cleanup:
    EVP_MD_CTX_free(ctx);
    return ret;
}

static ErasecureError evp_hash_file(const EVP_MD *md, const char *path,
                                    uint8_t *digest, unsigned int *digest_len)
{
    if (!path) return ERASECURE_ERR_INVALID_ARG;

    FILE *f = fopen(path, "rb");
    if (!f) return ERASECURE_ERR_OPEN_FAILED;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fclose(f); return ERASECURE_ERR_CRYPTO; }

    ErasecureError ret = ERASECURE_OK;
    uint8_t buf[65536];
    size_t n;

    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
        ret = ERASECURE_ERR_HASH_FAILED;
        goto cleanup;
    }

    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, n) != 1) {
            ret = ERASECURE_ERR_HASH_FAILED;
            goto cleanup;
        }
    }

    if (ferror(f)) {
        ret = ERASECURE_ERR_READ_FAILED;
        goto cleanup;
    }

    if (EVP_DigestFinal_ex(ctx, digest, digest_len) != 1) {
        ret = ERASECURE_ERR_HASH_FAILED;
        goto cleanup;
    }

cleanup:
    EVP_MD_CTX_free(ctx);
    fclose(f);
    return ret;
}

/* ─── Public API ─────────────────────────────────────────────── */

ErasecureError hash_sha256_buffer(const uint8_t *data, size_t data_len,
                                  uint8_t digest[ERASECURE_SHA256_DIGEST_LEN])
{
    if (!data || !digest) return ERASECURE_ERR_INVALID_ARG;
    unsigned int dlen = 0;
    return evp_hash_buffer(EVP_sha256(), data, data_len, digest, &dlen);
}

ErasecureError hash_sha512_buffer(const uint8_t *data, size_t data_len,
                                  uint8_t digest[ERASECURE_SHA512_DIGEST_LEN])
{
    if (!data || !digest) return ERASECURE_ERR_INVALID_ARG;
    unsigned int dlen = 0;
    return evp_hash_buffer(EVP_sha512(), data, data_len, digest, &dlen);
}

ErasecureError hash_sha256_file(const char *path,
                                uint8_t digest[ERASECURE_SHA256_DIGEST_LEN])
{
    if (!path || !digest) return ERASECURE_ERR_INVALID_ARG;
    unsigned int dlen = 0;
    return evp_hash_file(EVP_sha256(), path, digest, &dlen);
}

ErasecureError hash_sha512_file(const char *path,
                                uint8_t digest[ERASECURE_SHA512_DIGEST_LEN])
{
    if (!path || !digest) return ERASECURE_ERR_INVALID_ARG;
    unsigned int dlen = 0;
    return evp_hash_file(EVP_sha512(), path, digest, &dlen);
}

void hash_digest_to_hex(const uint8_t *digest, size_t digest_len,
                        char *hex_out)
{
    if (!digest || !hex_out) return;
    for (size_t i = 0; i < digest_len; ++i) {
        /* snprintf guaranteed to write 2 chars + NUL */
        snprintf(hex_out + i * 2, 3, "%02x", (unsigned int)digest[i]);
    }
    hex_out[digest_len * 2] = '\0';
}
