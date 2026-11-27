package com.digital.signature.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class OcspForwarderTest {
    private final OcspForwarder forwarder =
            new OcspForwarder(Duration.ofSeconds(2), Duration.ofSeconds(5));
    private final AtomicReference<String> contentType = new AtomicReference<>();
    private final AtomicReference<String> forwardedHeader = new AtomicReference<>();
    private final AtomicReference<byte[]> receivedBody = new AtomicReference<>();
    private HttpServer server;
    private int status = 200;
    private byte[] answer = {48, 3, 10, 1, 6};

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(
                "/ocsp",
                exchange -> {
                    contentType.set(exchange.getRequestHeaders().getFirst("Content-Type"));
                    forwardedHeader.set(
                            exchange.getRequestHeaders().getFirst(OcspForwarder.FORWARDED_HEADER));
                    receivedBody.set(exchange.getRequestBody().readAllBytes());
                    exchange.getResponseHeaders().add("Content-Type", "application/ocsp-response");
                    exchange.sendResponseHeaders(status, answer.length == 0 ? -1 : answer.length);
                    try (OutputStream out = exchange.getResponseBody()) {
                        out.write(answer);
                    }
                });
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    private URI url() {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/ocsp");
    }

    @Test
    void postsTheRequestAndReturnsTheAnswer() throws Exception {
        assertThat(forwarder.forward(url(), new byte[] {1, 2, 3})).containsExactly(answer);
        assertThat(receivedBody.get()).containsExactly(1, 2, 3);
        assertThat(contentType.get()).isEqualTo("application/ocsp-request");
        assertThat(forwardedHeader.get()).isEqualTo("1");
    }

    @Test
    void nonOkHttpStatusFails() {
        status = 404;

        assertThatThrownBy(() -> forwarder.forward(url(), new byte[] {1}))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("HTTP 404");
    }

    @Test
    void emptyAnswerFails() {
        answer = new byte[0];

        assertThatThrownBy(() -> forwarder.forward(url(), new byte[] {1}))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("empty");
    }

    @Test
    void unreachableResponderFails() throws Exception {
        final int freePort;
        try (ServerSocket socket = new ServerSocket(0)) {
            freePort = socket.getLocalPort();
        }

        assertThatThrownBy(
                        () ->
                                forwarder.forward(
                                        URI.create("http://127.0.0.1:" + freePort + "/ocsp"),
                                        new byte[] {1}))
                .isInstanceOf(IOException.class);
    }
}
