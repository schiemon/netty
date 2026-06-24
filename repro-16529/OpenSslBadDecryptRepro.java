import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.AdaptiveByteBufAllocator;
import io.netty.buffer.ByteBuf;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.*;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.handler.ssl.util.SelfSignedCertificate;

import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * End-to-end reproducer for the literal OpenSSL BAD_DECRYPT in netty/netty#16529.
 *
 * Runs many concurrent OpenSSL (tcnative) TLS connections that echo large random
 * payloads, under the AdaptiveByteBufAllocator (Netty 4.2 default). On 4.2.10-4.2.13
 * the allocator's BuddyChunk.remainingCapacity() data race (#16767) aliases buffer
 * memory; when an aliased buffer holds TLS ciphertext, OpenSSL fails its record MAC:
 *   javax.net.ssl.SSLException: ... OPENSSL_internal:BAD_DECRYPT
 *
 * REQUIREMENTS (cannot run on Apple Silicon — no osx-aarch64 tcnative native):
 *   - linux-x86_64 (or osx-x86_64) with netty-tcnative-boringssl-static on the classpath
 *   - netty 4.2.13.Final to reproduce; 4.2.14.Final+ to confirm the fix
 *   - run with:  -ea -Dio.netty.availableProcessors=2   (forces allocator contention)
 *
 * It is probabilistic (matches the reporter's "5-10/day"): loop until it trips.
 */
public final class OpenSslBadDecryptRepro {

    static final int CONNS = 64;
    static final int MSG_SIZE = 48 * 1024; // large -> ciphertext routes through BuddyChunk
    static final int MSGS_PER_CONN = 5000;

    static final AtomicReference<Throwable> failure = new AtomicReference<>();
    static final AtomicLong verified = new AtomicLong();

    public static void main(String[] args) throws Exception {
        SelfSignedCertificate cert = new SelfSignedCertificate();
        final SslContext serverCtx = SslContextBuilder.forServer(cert.certificate(), cert.privateKey())
                .sslProvider(SslProvider.OPENSSL).build();
        final SslContext clientCtx = SslContextBuilder.forClient()
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .sslProvider(SslProvider.OPENSSL).build();

        // Force the adaptive allocator explicitly (it is already the 4.2 default).
        final AdaptiveByteBufAllocator alloc = new AdaptiveByteBufAllocator();

        EventLoopGroup boss = new NioEventLoopGroup(1);
        EventLoopGroup workers = new NioEventLoopGroup();
        try {
            ServerBootstrap sb = new ServerBootstrap();
            sb.group(boss, workers).channel(NioServerSocketChannel.class)
                    .childOption(ChannelOption.ALLOCATOR, alloc)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override protected void initChannel(SocketChannel ch) {
                            ch.pipeline().addLast(serverCtx.newHandler(ch.alloc()));
                            ch.pipeline().addLast(new ChannelInboundHandlerAdapter() {
                                @Override public void channelRead(ChannelHandlerContext ctx, Object msg) {
                                    ctx.writeAndFlush(msg); // echo ciphertext back
                                }
                                @Override public void exceptionCaught(ChannelHandlerContext ctx, Throwable t) {
                                    failure.compareAndSet(null, t);
                                    ctx.close();
                                }
                            });
                        }
                    });
            Channel server = sb.bind(0).sync().channel();
            int port = ((InetSocketAddress) server.localAddress()).getPort();

            Bootstrap cb = new Bootstrap();
            cb.group(workers).channel(NioSocketChannel.class)
                    .option(ChannelOption.ALLOCATOR, alloc)
                    .handler(new ChannelInitializer<SocketChannel>() {
                        @Override protected void initChannel(SocketChannel ch) {
                            ch.pipeline().addLast(clientCtx.newHandler(ch.alloc()));
                            ch.pipeline().addLast(new EchoVerifier());
                        }
                    });

            for (int i = 0; i < CONNS; i++) {
                cb.connect("127.0.0.1", port);
            }

            long deadline = System.nanoTime() + 5L * 60 * 1_000_000_000L;
            while (failure.get() == null && System.nanoTime() < deadline) {
                Thread.sleep(500);
                System.out.println("verified messages: " + verified.get());
            }

            Throwable f = failure.get();
            if (f != null) {
                System.out.println("RESULT: FAILURE <-- reproduced");
                f.printStackTrace(System.out);
                System.exit(2);
            } else {
                System.out.println("RESULT: no failure within time budget (re-run; it is probabilistic)");
            }
        } finally {
            boss.shutdownGracefully();
            workers.shutdownGracefully();
        }
    }

    /** Client handler: writes a known payload, verifies the echo byte-for-byte. */
    static final class EchoVerifier extends ChannelInboundHandlerAdapter {
        private byte tag;
        private int outstanding;
        private int sent;

        private void send(ChannelHandlerContext ctx) {
            tag = (byte) (ctx.channel().hashCode() ^ sent);
            ByteBuf b = ctx.alloc().buffer(MSG_SIZE);
            for (int i = 0; i < MSG_SIZE; i++) {
                b.writeByte(tag);
            }
            outstanding = MSG_SIZE;
            sent++;
            ctx.writeAndFlush(b);
        }

        @Override public void channelActive(ChannelHandlerContext ctx) {
            send(ctx);
        }

        @Override public void channelRead(ChannelHandlerContext ctx, Object msg) {
            ByteBuf in = (ByteBuf) msg;
            try {
                while (in.isReadable()) {
                    if (in.readByte() != tag) {
                        failure.compareAndSet(null,
                                new IllegalStateException("decrypted plaintext corrupted (aliasing)"));
                        ctx.close();
                        return;
                    }
                    outstanding--;
                }
                if (outstanding == 0) {
                    verified.incrementAndGet();
                    if (sent < MSGS_PER_CONN) {
                        send(ctx);
                    }
                }
            } finally {
                in.release();
            }
        }

        @Override public void exceptionCaught(ChannelHandlerContext ctx, Throwable t) {
            // BAD_DECRYPT surfaces here as javax.net.ssl.SSLException
            failure.compareAndSet(null, t);
            ctx.close();
        }
    }
}
