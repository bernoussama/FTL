# PTR response test vectors

Inputs and observed results of `test/ptr_response_regression.c`, the regression
harness for the PTR path of `resolveHostname()` (`src/resolve.c`). A fake DNS
server on 127.0.0.1 answers FTL's reverse lookups. The Rust implementation is
tested against the same cases.

## Files

- `manifest.json`: every vector, in the order the packets were sent. A query
  comes before its reply.
- `<case>-<NN>-query.bin`: the query as the fake server received it.
- `<case>-<NN>-response.bin`: a reply the fake server sent.

`<case>` is the harness test name and `<NN>` counts exchanges per case from 01.
The manifest links each query to its reply: `args.answered_by` on the query,
`args.answers_query` on the reply.

Cases:

- `stale_reply_then_valid`: the lookup of 192.0.2.10 gets no reply in time. Its
  reply arrives late, during the lookup of 192.0.2.11, and must be discarded
  because its ID belongs to the earlier query. The reply to the second query
  (`answer-b.example`) is accepted.
- `invalid_name_bang`, `invalid_name_space`, `invalid_name_empty`: one PTR reply
  with a name containing `!` (offset 3), a space (offset 2), or nothing. The
  invalid names are rejected and the HOSTNAME warning gives the offset of the
  invalid character. The empty name is rejected without a warning.

## Manifest schema

```json
{
	"module": "ptr_response",
	"generator": "test/ptr_response_regression.c",
	"vectors": [
		{
			"file": "stale_reply_then_valid-02-query.bin",
			"test": "stale_reply_then_valid",
			"op": "resolveHostname",
			"args": { "packet": "query", "exchange": 2, "lookup_addr": "192.0.2.11", "qtype": 12, "qclass": 1, "tcp": false, "force": true, "resolver_timeout_ms": 2000, "answered_by": "stale_reply_then_valid-02-response.bin" },
			"expect": { "outcome": "name", "name": "answer-b.example", "hostname_warning": null }
		}
	]
}
```

- `file`: the packet, relative to this directory. `test`: the harness case.
- `op`: always `resolveHostname`, the function that gets this packet as input.
- `args`, query entries:
  - `packet`: `"query"`. `exchange`: the `<NN>` of the file name.
  - `lookup_addr`: the address that was looked up. `qtype`, `qclass`: 12 (PTR)
    and 1 (IN).
  - `tcp`: false (UDP). `force`: true, so the name is resolved even when name
    resolution is turned off in the configuration.
  - `resolver_timeout_ms`: how long the lookup waits for a reply (a number).
  - `answered_by`: the reply file for this exchange.
- `args`, response entries:
  - `packet`: `"response"`. `exchange`: the `<NN>` of the file name.
  - `answers_query`: the query file this reply answers.
  - `ptr_target`: the name in the PTR record, as sent.
  - `delivered_during_lookup`: the address of the lookup whose call reads this
    reply.
  - `delay_ms`: how long the fake server held the reply (a number).
- `expect`, query entries (what `resolveHostname()` returned):
  - `outcome`: `"name"` (a name was returned), `"timeout"` (no reply within
    `resolver_timeout_ms`; this is the harness's `FIRST_LOOKUP_TIMEOUT` check),
    or `"no_name"` (a reply came but gave no usable name).
  - `name`: the returned name, or null.
  - `hostname_warning`: null, or `{ "name", "pos" }`: the rejected name and the
    offset of its first invalid character.
- `expect`, response entries (what FTL did with this packet):
  - `accepted`: true when FTL took its name from this packet.
  - `name`: the name taken, or null.
  - `reason`: why the packet was rejected, or null when it was accepted.

There is no `c_log` field: the harness does not assert on log messages.

## Timing

`delay_ms` and `resolver_timeout_ms` are plain numbers in `args`. The timing
itself is not in the data files, and only the C harness enforces it. The fake
server holds the reply to the first lookup until that lookup has timed out
(`delay_ms` = `resolver_timeout_ms` = 2000). A replay has to keep the same
order: the first reply reaches FTL only after the first lookup has timed out,
and before the answer to the second lookup.

## Query IDs

The IDs are not random here. The harness's `get_secure_randomness()` stub hands
out bytes 1, 2, 3, ... in call order, so the query IDs are fixed. The files
keep them unchanged (not normalized). Each reply echoes the ID of the query it
answers. A replay that generates its own IDs must rewrite the 2-byte ID of each
reply to the ID of the query it answers.

## Regenerating

Run from the repository root. This builds in docker, exports, and copies the
result here. The plain harness run comes first, and it must pass.

```sh
test/docker-test.sh build
test/docker-test.sh run bash -c \
  './ptr_response_regression && rm -rf /logs/v && ./ptr_response_regression --export-vectors /logs/v; rc=$?; chown -R $HOST_UID:$HOST_GID /logs; exit $rc'
cp build-docker/logs/v/* test/vectors/ptr_response/
```
