# Tar parser test vectors

Inputs and observed results of `test/tar_regression.c`, the regression harness
for FTL's in-memory tar reader (`src/zip/tar.c`: `find_file_in_tar()` and
`list_files_in_tar()`). The Rust implementation is tested against the same
cases.

## Files

- `manifest.json`: every vector, in run order.
- `<test>-<NN>.tar`: one input per vector, the exact bytes handed to FTL (the
  file length is the `tarSize` argument). `<test>` is a case name from the
  harness table (`./tar_regression --list`), `<NN>` counts from 01 per case.

Covered cases: short archives (0, 16 and 511 bytes), size-field boundaries
(0, 1, 511, 512, 513), invalid size fields, a huge size with no payload, a
leading-space size field (accepted), truncated payloads, short and truncated
sample archives, missing padding, non-terminated names, skipping entries
(payloads of 1, 512 and 513 bytes), and a malformed second entry.

Some inputs appear twice: a case that calls both find and list on one buffer
writes that buffer under two names, one per call.

## Manifest schema

```json
{
	"module": "tar",
	"generator": "test/tar_regression.c",
	"vectors": [
		{
			"file": "short-archives-01.tar",
			"test": "short-archives",
			"op": "find_file_in_tar",
			"args": { "name": "entry" },
			"expect": { "found": false, "file_size": 0 }
		}
	]
}
```

- `file`: the input, relative to this directory.
- `test`: the harness case that produced the call.
- `op`: the FTL function called on the input.
- `args`: the call arguments other than the archive bytes.
  - `find_file_in_tar`: `name`, the entry name looked up.
  - `list_files_in_tar`: empty.
- `expect`: what FTL returned, as observed from the C code.
  - `find_file_in_tar`:
    - `found`: `false` when FTL returned NULL. That covers both "no entry
      matched" and "the archive was rejected", which the C API does not
      distinguish. The `test` name shows the intent.
    - `file_size`: the `fileSize` value after the call (0 when not found).
    - `payload_offset`: present only when found. The payload is the input
      bytes `[payload_offset, payload_offset + file_size)`.
  - `list_files_in_tar`:
    - `files`: the array of `{ "name", "size" }` entries listed before the
      parser stopped. A malformed or truncated archive shows up as a shorter
      list. The C API has no error return, so there is no `rejected` field.

No `c_log` field: the harness does not assert on C log messages.

## Not exported

- `tar_entry_span()` takes a size, not an archive, so it has no input file and
  is not exported. Its results only set the sizes of the recorded inputs; its
  direct checks stay in the harness.
- `parse_tar_size()` is reached only through find and list, so its results are
  already in the vectors.

## Regenerating

Run from the repository root. This builds in docker, exports, and copies the
result here.

```sh
test/docker-test.sh build
test/docker-test.sh run bash -c \
  'rm -rf /logs/v && ./tar_regression --export-vectors /logs/v; rc=$?; chown -R $HOST_UID:$HOST_GID /logs; exit $rc'
cp build-docker/logs/v/* test/vectors/tar/
```

`OUT_DIR` and `LOG_DIR` override the default `build-docker` locations. The
export is deterministic: two runs give byte-identical output.
