/**
 * @file hash.h
 * @brief SHA-256 and SHA-512 hashing via OpenSSL EVP API.
 */
#ifndef ERASECURE_HASH_H
#define ERASECURE_HASH_H

#include "common/types.h"
#include "common/error.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Compute SHA-256 of an in-memory buffer.
 *
 * @param data      Input buffer.
 * @param data_len  Length of input buffer in bytes.
 * @param digest    Output: 32-byte raw digest (caller provides buffer).
 * @return          ERASECURE_OK on success.
 */
ErasecureError hash_sha256_buffer(const uint8_t *data, size_t data_len,
                                  uint8_t digest[ERASECURE_SHA256_DIGEST_LEN]);

/**
 * @brief Compute SHA-512 of an in-memory buffer.
 */
ErasecureError hash_sha512_buffer(const uint8_t *data, size_t data_len,
                                  uint8_t digest[ERASECURE_SHA512_DIGEST_LEN]);

/**
 * @brief Compute SHA-256 of a file.
 *
 * Reads the file in streaming chunks.
 *
 * @param path    File path.
 * @param digest  Output: 32-byte raw digest.
 * @return        ERASECURE_OK on success.
 */
ErasecureError hash_sha256_file(const char *path,
                                uint8_t digest[ERASECURE_SHA256_DIGEST_LEN]);

/**
 * @brief Compute SHA-512 of a file.
 */
ErasecureError hash_sha512_file(const char *path,
                                uint8_t digest[ERASECURE_SHA512_DIGEST_LEN]);

/**
 * @brief Convert a raw digest to lowercase hex string.
 *
 * @param digest     Raw binary digest.
 * @param digest_len Length of digest in bytes.
 * @param hex_out    Output buffer; must hold at least digest_len*2+1 bytes.
 */
void hash_digest_to_hex(const uint8_t *digest, size_t digest_len,
                        char *hex_out);

#endif /* ERASECURE_HASH_H */
