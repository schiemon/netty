import io.netty.buffer.AdaptiveByteBufAllocator;
import io.netty.buffer.ByteBuf;

import java.util.ArrayList;
import java.util.List;
import java.util.SplittableRandom;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Root-cause reproducer for netty/netty#16529 (the BAD_DECRYPT mechanism).
 *
 * Netty 4.2 made AdaptiveByteBufAllocator the DEFAULT (4.1 used pooled), so the
 * upgrade silently switched everyone onto it. BuddyChunk.remainingCapacity() —
 * a query that must be read-only — drained the freeList and mutated the shared
 * buddies[] array. remainingCapacity() is called from shared chunk-scan paths
 * WITHOUT exclusive access, so concurrent callers race and corrupt the buddies[]
 * metadata. The allocator can then hand the SAME memory to two live buffers.
 *
 * That memory aliasing is exactly what corrupts in-flight TLS ciphertext ->
 * OpenSSL BAD_DECRYPT (and HTTP/2 frame data -> content-length mismatch).
 *
 * This reproducer needs NO TLS/native libs: it stresses the allocator the way the
 * fix's regression test does (concurrent allocate + ensureWritable growth) and
 * additionally writes a per-buffer fingerprint, grows, and verifies the bytes are
 * unchanged. Two failure signals on the buggy allocator, neither on the fixed one:
 *   1. AssertionError / exception from corrupted allocator metadata (run with -ea)
 *   2. CONTENT CORRUPTION: a buffer reads back bytes it never wrote (memory aliasing)
 */
public final class AllocRepro {

    static final int THREADS = Integer.getInteger("repro.threads", 32);
    static final int ITERS = Integer.getInteger("repro.iters", 3000);
    static final int ROUNDS = Integer.getInteger("repro.rounds", 40);
    // All sizes target BuddyChunk (> max size-class 16896, MIN_BUDDY_SIZE 32768).

    public static void main(String[] args) throws Exception {
        AdaptiveByteBufAllocator allocator = new AdaptiveByteBufAllocator(false); // heap
        ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        AtomicReference<Throwable> firstFailure = new AtomicReference<>();
        AtomicReference<String> firstCorruption = new AtomicReference<>();

        for (int round = 0; round < ROUNDS && firstFailure.get() == null
                && firstCorruption.get() == null; round++) {
            // Always exercise BuddyChunk: requests above the 16896 size-class ceiling.
            final int base = 20000;
            final int extra = 60000;
            final int growth = 90000;

            CountDownLatch start = new CountDownLatch(1);
            List<Future<?>> futures = new ArrayList<>();
            for (int t = 0; t < THREADS; t++) {
                final byte tag = (byte) (t + 1); // unique non-zero fingerprint per thread
                futures.add(pool.submit(() -> {
                    start.await();
                    SplittableRandom rng = new SplittableRandom();
                    for (int i = 0; i < ITERS && firstCorruption.get() == null; i++) {
                        int initial = base + rng.nextInt(extra);
                        ByteBuf buf = allocator.heapBuffer(initial);
                        try {
                            // fingerprint the readable region
                            for (int j = 0; j < initial; j++) {
                                buf.writeByte(tag);
                            }
                            // grow: allocates new memory, copies, frees old (exercises remainingCapacity)
                            buf.ensureWritable(rng.nextInt(growth) + 1);
                            // verify our bytes survived — a mismatch means another buffer aliased ours
                            for (int j = 0; j < initial; j++) {
                                if (buf.getByte(j) != tag) {
                                    firstCorruption.compareAndSet(null, "thread " + tag
                                            + " saw 0x" + Integer.toHexString(buf.getByte(j) & 0xff)
                                            + " at index " + j + " (expected 0x"
                                            + Integer.toHexString(tag & 0xff) + ") size=" + initial);
                                    break;
                                }
                            }
                        } finally {
                            buf.release();
                        }
                    }
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> f : futures) {
                try {
                    f.get(60, TimeUnit.SECONDS);
                } catch (Throwable th) {
                    firstFailure.compareAndSet(null, th.getCause() != null ? th.getCause() : th);
                }
            }
            System.out.println("round " + round + " done");
        }

        pool.shutdownNow();

        Throwable fail = firstFailure.get();
        String corruption = firstCorruption.get();
        if (fail != null) {
            System.out.println("RESULT: ALLOCATOR FAILURE (corrupted metadata) <-- BUG");
            fail.printStackTrace(System.out);
            System.exit(2);
        } else if (corruption != null) {
            System.out.println("RESULT: CONTENT CORRUPTION (memory aliasing) <-- BAD_DECRYPT root cause");
            System.out.println("  " + corruption);
            System.exit(3);
        } else {
            System.out.println("RESULT: OK (no corruption observed)");
            System.exit(0);
        }
    }
}
