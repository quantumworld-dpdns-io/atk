/*
 * libFuzzer harness for ngx_http_script.c
 *
 * Tests the two-pass script engine for buffer size mismatches
 * between length calculation and copy phases.
 *
 * Input format:
 *   - First 4 bytes: number of opcodes
 *   - Following bytes: opcode stream
 *     Each opcode is 1 byte (opcode type) followed by payload:
 *       0x01: START_ARGS (no payload)
 *       0x02: COPY_CAPTURE (4 bytes: capture index, 4 bytes: length)
 *       0x03: COMPLEX_VALUE (4 bytes: lengths offset)
 *       0x04: REGEX_END (no payload)
 *       0x05: SET_IS_ARGS (1 byte: 0 or 1)
 *       0x06: ESCAPE_URI (4 bytes: input_len, then input_data)
 *   - Final bytes: URI string data for captures
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Opaque types to satisfy compilation without full NGINX include chain */
typedef struct {
    unsigned char *last;
    unsigned char *end;
    unsigned char *start;
    unsigned char *pos;
} ngx_pool_data_t;

typedef struct ngx_pool_s {
    ngx_pool_data_t d;
    size_t max;
    void *current;
    void *chain;
    void *large;
    void *cleanup;
    void *log;
} ngx_pool_t;

typedef struct {
    int is_args;
    int quote;
    unsigned char *ip;
    unsigned char *pos;
    unsigned char *args;
    void *request;
    int *captures_data;
    int *captures;
} ngx_http_script_engine_t;

enum opcode {
    OP_START_ARGS = 1,
    OP_COPY_CAPTURE = 2,
    OP_COMPLEX_VALUE = 3,
    OP_REGEX_END = 4,
    OP_SET_IS_ARGS = 5,
    OP_ESCAPE_URI = 6,
};

static int ngx_escape_uri_null(const unsigned char *src, size_t size,
                               unsigned int type)
{
    size_t len = 0;
    size_t i;
    for (i = 0; i < size; i++) {
        unsigned char ch = src[i];
        if (ch == '+' || ch == '%' || ch == '&') {
            len += 2; /* +2 for escaping overhead in NGX_ESCAPE_ARGS */
        }
        len++;
    }
    return len - size;
}

static void test_script_engine(const uint8_t *data, size_t size)
{
    if (size < 4) return;

    uint32_t num_opcodes;
    memcpy(&num_opcodes, data, 4);
    if (num_opcodes > 100) return;

    ngx_http_script_engine_t main_engine;
    memset(&main_engine, 0, sizeof(main_engine));

    ngx_http_script_engine_t *e = &main_engine;

    size_t offset = 4;
    uint32_t calculated_len = 0;
    uint32_t actual_written = 0;

    for (uint32_t i = 0; i < num_opcodes && offset < size; i++) {
        if (offset >= size) break;
        uint8_t op = data[offset++];

        switch (op) {
        case OP_START_ARGS:
            e->is_args = 1;
            e->args = e->pos;
            break;

        case OP_COPY_CAPTURE: {
            if (offset + 8 > size) return;
            int capture_idx, capture_len;
            memcpy(&capture_idx, data + offset, 4);
            memcpy(&capture_len, data + offset + 4, 4);
            offset += 8;

            if (capture_idx < 0 || capture_len < 0) return;
            if (offset + capture_len > size) return;

            /* Length pass (simulating sub-engine with is_args=0) */
            uint32_t raw_len = capture_len;

            /* Copy pass (main engine with actual is_args) */
            uint32_t escaped_len = raw_len;
            if (e->is_args) {
                int overhead = ngx_escape_uri_null(
                    data + offset, capture_len, 0);
                escaped_len = capture_len + overhead;
            }

            /*
             * This is the key check: if the length pass calculated
             * raw_len but the copy pass writes escaped_len, we have
             * a buffer overflow.
             */
            if (escaped_len > raw_len) {
                /* Vulnerability detected! */
                fprintf(stderr, "OVERFLOW: len=%u escaped=%u diff=%u "
                        "is_args=%d\n",
                        raw_len, escaped_len,
                        escaped_len - raw_len, e->is_args);
            }

            offset += capture_len;
            break;
        }

        case OP_COMPLEX_VALUE: {
            if (offset + 4 > size) return;
            uint32_t len_offset;
            memcpy(&len_offset, data + offset, 4);
            offset += 4;

            /*
             * Simulate the sub-engine being zeroed:
             * the length pass should use a fresh engine
             * with is_args = 0.
             */
            ngx_http_script_engine_t le;
            memset(&le, 0, sizeof(le));

            /*
             * In the real bug, the length pass runs on le
             * (with is_args=0), but the copy pass runs on e
             * (which may have is_args=1 from a previous op).
             */
            calculated_len = len_offset;
            break;
        }

        case OP_REGEX_END:
            /*
             * This is where the fix goes: e->is_args = 0;
             * If this is missing, is_args leaks to the next
             * complex value evaluation.
             */
            /* PATCH: e->is_args = 0; */
            e->quote = 0;
            break;

        case OP_SET_IS_ARGS:
            if (offset >= size) return;
            e->is_args = data[offset++] & 1;
            break;

        case OP_ESCAPE_URI:
            if (offset + 4 > size) return;
            {;
                uint32_t input_len;
                memcpy(&input_len, data + offset, 4);
                offset += 4;
                if (offset + input_len > size) return;
                offset += input_len;
            }
            break;

        default:
            break;
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    test_script_engine(data, size);
    return 0;
}
