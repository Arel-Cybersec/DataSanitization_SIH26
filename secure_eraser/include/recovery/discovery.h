#ifndef ERASECURE_DISCOVERY_H
#define ERASECURE_DISCOVERY_H

#include "common/types.h"
#include "common/error.h"
#include "recovery/file_mirror.h"
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    const uint8_t *bytes;      /* Signature byte pattern */
    size_t         length;     /* Pattern length */
    int64_t        offset;     /* Offset within block (0 = start of block) */
    bool           is_footer;  /* true for footer signatures */
    const char    *type_name;  /* Associated file type name */
} SignaturePattern;

typedef struct {
    uint64_t    block;         /* Block where signature found */
    uint64_t    byte_offset;   /* Exact byte offset within image */
    const char *type_name;     /* File type name */
    bool        is_footer;
} SignatureHit;

typedef struct {
    SignaturePattern *patterns;    /* Registered patterns */
    size_t            pattern_count;
    size_t            pattern_capacity;
    SignatureHit     *hits;        /* Discovered signatures */
    size_t            hit_count;
    size_t            hit_capacity;
} DiscoveryEngine;

ErasecureError discovery_init(DiscoveryEngine *engine);
void discovery_destroy(DiscoveryEngine *engine);
ErasecureError discovery_register_signature(DiscoveryEngine *engine, const SignaturePattern *pattern);
ErasecureError discovery_scan(DiscoveryEngine *engine, const FileMirror *fm);
size_t discovery_hit_count(const DiscoveryEngine *engine);
const SignatureHit *discovery_get_hit(const DiscoveryEngine *engine, size_t index);
ErasecureError discovery_get_headers_for_type(const DiscoveryEngine *engine, const char *type_name, const SignatureHit **out_hits, size_t *out_count);
ErasecureError discovery_get_footers_for_type(const DiscoveryEngine *engine, const char *type_name, const SignatureHit **out_hits, size_t *out_count);

#endif
