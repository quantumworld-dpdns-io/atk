# Fuzzer Corpus

Seed inputs for the libFuzzer harness targeting ngx_http_script.c
two-pass engine.

## Seed 1: Basic rewrite+set (vulnerable pattern)

Binary: [OP_START_ARGS] [OP_COPY_CAPTURE idx=1 len=10 "AAAAAAAAAA"]
        [OP_COMPLEX_VALUE len=10] [OP_REGEX_END]
        [OP_COPY_CAPTURE idx=1 len=10 "BBBBBBBBBB"]

This seed triggers the exact bug: is_args is set by START_ARGS,
COMPLEX_VALUE computes length with zeroed sub-engine, COPY_CAPTURE
writes with is_args=1.

## Seed 2: No rewrite (should not trigger)

Binary: [OP_SET_IS_ARGS=0] [OP_COPY_CAPTURE idx=1 len=5 "CCCCC"]
        [OP_REGEX_END]

## Seed 3: With named captures (should not trigger)

Binary: [OP_SET_IS_ARGS=0] [OP_COMPLEX_VALUE len=8]
        [OP_REGEX_END]

## Seed 4: Multiple rewrite directives

Binary: [OP_START_ARGS] [OP_COPY_CAPTURE idx=1 len=5 "DDDDD"]
        [OP_START_ARGS] [OP_COPY_CAPTURE idx=2 len=7 "EEEEEEE"]
        [OP_COMPLEX_VALUE len=12] [OP_REGEX_END]

## Seed 5: Nested complex values

Binary: [OP_START_ARGS] [OP_COMPLEX_VALUE len=3]
        [OP_COMPLEX_VALUE len=3] [OP_COPY_CAPTURE idx=1 len=3 "FFF"]
        [OP_REGEX_END]
