# Issue #16529 — handoff to a Linux agent

Issue: https://github.com/netty/netty/issues/16529
Two intermittent errors appeared after upgrading 4.1.131.Final → 4.2.x and disappeared
at 4.2.14.Final:
1. `javax.net.ssl.SSLException: ...OPENSSL_internal:BAD_DECRYPT` (OpenSSL/tcnative)
2. `Http2Exception$StreamException: Received amount of data X does not match content-length Y`,
   with the gap exactly `16384` (HTTP/2 `MAX_FRAME_SIZE`).

## Root cause (confirmed)

A data race in `AdaptivePoolingAllocator` (PR #16767), **not** SSL/HTTP2 code.

- Netty 4.2 changed the **default** `ByteBufAllocator` from `pooled` (4.1) to `adaptive`.
  The upgrade silently moved everyone onto `AdaptiveByteBufAllocator`.
- `BuddyChunk.remainingCapacity()` — a query that must be read-only — called
  `freeList.drain(...)`, mutating the shared `buddies[]` array. It is invoked from shared
  chunk-scan paths **without exclusive access**, so concurrent callers corrupt the metadata
  and the allocator can hand the **same memory to two live buffers**.
- Aliased ciphertext → OpenSSL `BAD_DECRYPT`. Aliased HTTP/2 DATA frame → content-length
  mismatch off by one `MAX_FRAME_SIZE`.
- Present since 4.2.10 (when adaptive became the default); fixed in **4.2.14.Final** by #16767.
- Fix: `BuddyChunk.remainingCapacity()` no longer drains; it sums via `weakPeekReduce`.

A separate `CompositeByteBuf` fast-path bug (#16548/#16811) was also reverted in 4.2.14 and was
my first (wrong) guess. It is ruled out: OpenSSL reads ciphertext via `nioBuffers()` (no
`readByte()` fast path), HTTP/2 uses `MERGE_CUMULATOR` (not composite), and the fast path only
existed in 4.2.13 — it cannot explain the 4.2.10 sightings. Ignore it for this issue.

## Verified locally (macOS / Apple Silicon, aarch64)

`AllocRepro.java` — pure-allocator reproducer, no TLS/native libs. Concurrent
allocate + `ensureWritable` growth; each buffer is fingerprinted and verified to read back
unchanged. Run with `-ea -Dio.netty.availableProcessors=2` (forces allocator contention).

- buggy allocator (4.2.13.Final): **CONTENT CORRUPTION (memory aliasing)** — a buffer reads
  bytes another thread wrote. Hit ~2 of 3 runs (probabilistic, matches "5-10/day").
- fixed allocator (4.2.14.Final): clean across 40 rounds, repeated.

This proves the exact mechanism behind BAD_DECRYPT (two buffers sharing memory).

## NOT reproduced locally — needs a Linux agent

The **literal OpenSSL `BAD_DECRYPT`** end-to-end. This box is Apple Silicon and the local maven
repo only has `netty-tcnative-boringssl-static` for `linux-x86_64` / `osx-x86_64`, so the
BoringSSL native won't load here. `OpenSslBadDecryptRepro.java` is written but UNRUN.

### Task for the Linux agent

Environment: linux-x86_64, JDK 11+, `netty-tcnative-boringssl-static` (the `linux-x86_64`
classifier) on the classpath.

1. Confirm the allocator mechanism on Linux:
   - Run `AllocRepro` against `netty-buffer:4.2.13.Final` → expect CONTENT CORRUPTION
     (loop a few times; probabilistic).
   - Run `AllocRepro` against `netty-buffer:4.2.14.Final` → expect OK.
   - JVM flags: `-ea -Dio.netty.availableProcessors=2`. Bump `repro.rounds`/`repro.threads` if needed.

2. Reproduce the literal BAD_DECRYPT end-to-end:
   - Run `OpenSslBadDecryptRepro` against **4.2.13.Final** → expect, within minutes,
     `javax.net.ssl.SSLException: ...OPENSSL_internal:BAD_DECRYPT` (or a plaintext-integrity
     failure). It is probabilistic; loop until it trips.
   - Run against **4.2.14.Final** → expect clean (no failure within the time budget).
   - JVM flags: `-ea -Dio.netty.availableProcessors=2`. Increase `CONNS` / `MSGS_PER_CONN`
     to raise contention if it doesn't trip.

Dependencies for both versions: `netty-buffer`, `netty-common`, `netty-handler`,
`netty-transport`, `netty-codec`, `netty-codec-http2` (for context), and
`netty-tcnative-boringssl-static` (linux-x86_64), plus `org.jctools:jctools-core`.

### What "success" looks like

- 4.2.13.Final: `OpenSslBadDecryptRepro` prints a stack trace containing `BAD_DECRYPT`.
- 4.2.14.Final: same harness runs clean.

That closes the loop from "allocator aliases memory" (verified here) to "OpenSSL reports
BAD_DECRYPT" (to verify on Linux).

## Notes / knobs

- `-Dio.netty.availableProcessors=2` shrinks the magazine count → far higher contention on a
  shared `BuddyChunk` → the race trips quickly. Without it, it can take much longer.
- Allocations must be `> 16896` bytes to route through `BuddyChunk` (where the bug lives);
  both reproducers already size for this.
- Workaround for anyone stuck on 4.2.10–4.2.13: `-Dio.netty.allocator.type=pooled`.
