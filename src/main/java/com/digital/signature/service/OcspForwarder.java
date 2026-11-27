package com.digital.signature.service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sends a DER OCSP request to another OCSP responder with HTTP POST and returns its DER answer.
 *
 * <p>Thread-safe: the underlying {@link HttpClient} is shared.
 */
public class OcspForwarder {
    /** Request header that marks an already forwarded request, so it is never forwarded again. */
    public static final String FORWARDED_HEADER = "X-OCSP-Test-Forwarded";

    private static final Logger LOGGER = LoggerFactory.getLogger(OcspForwarder.class);
    private static final String REQUEST_TYPE = "application/ocsp-request";
    private static final String RESPONSE_TYPE = "application/ocsp-response";
    private static final int MAX_RESPONSE_SIZE = 1_048_576;
    private static final int HTTP_OK = 200;
    private final HttpClient client;
    private final Duration timeout;

    /** Creates a forwarder with a 5 second connect and 15 second request timeout. */
    public OcspForwarder() {
        this(Duration.ofSeconds(5), Duration.ofSeconds(15));
    }

    /**
     * Creates a forwarder with the given timeouts.
     *
     * @param connectTimeout TCP connect timeout
     * @param timeout timeout of the whole request
     */
    public OcspForwarder(final Duration connectTimeout, final Duration timeout) {
        this.client =
                HttpClient.newBuilder()
                        .connectTimeout(connectTimeout)
                        .followRedirects(HttpClient.Redirect.NORMAL)
                        .build();
        this.timeout = timeout;
    }

    /**
     * Forwards the request.
     *
     * @param target URL of the other OCSP responder
     * @param request DER encoded OCSP request
     * @return the DER answer of the other responder
     * @throws IOException if the responder cannot be reached or does not answer with HTTP 200 and
     *     an OCSP response body
     */
    public byte[] forward(final URI target, final byte[] request) throws IOException {
        final HttpRequest httpRequest =
                HttpRequest.newBuilder(target)
                        .timeout(timeout)
                        .header("Content-Type", REQUEST_TYPE)
                        .header("Accept", RESPONSE_TYPE)
                        .header(FORWARDED_HEADER, "1")
                        .POST(HttpRequest.BodyPublishers.ofByteArray(request))
                        .build();
        final HttpResponse<byte[]> response;
        try {
            response = client.send(httpRequest, HttpResponse.BodyHandlers.ofByteArray());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Forwarding was interrupted", e);
        }
        final byte[] body = response.body();
        if (response.statusCode() != HTTP_OK) {
            throw new IOException(
                    "the responder answered HTTP "
                            + response.statusCode()
                            + " (content type "
                            + response.headers().firstValue("Content-Type").orElse("none")
                            + ")");
        }
        if (body == null || body.length == 0 || body.length > MAX_RESPONSE_SIZE) {
            throw new IOException(
                    "the responder answered with an empty or too large body ("
                            + (body == null ? 0 : body.length)
                            + " bytes)");
        }
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("OCSP forward to {} answered {} bytes", target, body.length);
        }
        return body;
    }
}
