# gzip test vectors

Inputs and observed results of the `gzip_regression` harness (`test/gzip_regression.c`)
for FTL's `inflate_buffer()` in `src/zip/gzip.c`. Each vector is one gzip stream that
the harness hands to `inflate_buffer()`, plus what the C code returned for it.

Coverage (one vector per harness case):

- Rejected: short stream, extra field overlapping the footer, name field starting in
  the footer, name field missing its NUL before the footer, name field terminator in
  the footer, comment field starting in the footer, comment field missing its NUL
  before the footer.
- Accepted: CRC32 with the high bit set, empty optional fields (FEXTRA, FNAME and
  FCOMMENT present but empty).

## Manifest (`manifest.json`)

    {"module": "gzip", "generator": "test/gzip_regression.c", "vectors": [ ... ]}

Each entry in `vectors`:

- `file`: the input, a binary file in this directory. It is the exact byte sequence
  handed to `inflate_buffer()`, before FTL mutates its scratch copy.
- `test`: the harness case that produced the vector.
- `op`: the FTL operation. Always `inflate_buffer`, meaning
  `inflate_buffer(buffer, size, &output, &output_size)` from `src/zip/gzip.c`.
- `args`: operation arguments. Empty, because the input file carries everything.
- `expect.rejected`: `true` if `inflate_buffer()` returned false.
- `expect.c_log`: present only for rejected inputs whose case asserts on the log. The
  message FTL logged when it rejected the input.
- `expect.output_size`: for accepted inputs, the number of decompressed bytes.
- `expect.output_sha256`: for accepted inputs, the SHA-256 (lowercase hex) of the
  decompressed bytes.

`expect` records what the C code actually did for the input. A rejected input is
expected to be rejected by a Rust implementation, and an accepted one is expected to
produce the same size and digest. The log text is C-specific and is only meant as a
reference.

## Regenerate

Run inside docker only (never on the host):

    OUT_DIR=$PWD/build-gzip CACHE_VOLUME=ftl-cmake-gzip test/docker-test.sh build
    OUT_DIR=$PWD/build-gzip FTL_BIN=$PWD/build-gzip/pihole-FTL LOG_DIR=$PWD/build-gzip/out \
      test/docker-test.sh run bash -c \
      './gzip_regression && rm -rf /logs/v && ./gzip_regression --export-vectors /logs/v; rc=$?; chown -R $HOST_UID:$HOST_GID /logs; exit $rc'
    cp build-gzip/out/v/* test/vectors/gzip/
