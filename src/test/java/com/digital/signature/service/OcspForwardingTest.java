package com.digital.signature.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.digital.signature.util.OcspTestPki;
import com.digital.signature.util.OcspTestPki.Ca;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class OcspForwardingTest {
    private static final String UPSTREAM = "http://upstream.example/ocsp";
    private final RecordingForwarder forwarder = new RecordingForwarder();
    private final OcspService service = new OcspService(forwarder);
    private Ca known;
    private Ca unknown;

    /** Records the forwarded requests and answers with a configurable result. */
    private static final class RecordingForwarder extends OcspForwarder {
        private final List<URI> targets = new ArrayList<>();
        private byte[] answer;
        private IOException failure;

        @Override
        public byte[] forward(final URI target, final byte[] request) throws IOException {
            targets.add(target);
            if (failure != null) {
                throw failure;
            }
            return answer;
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        known = OcspTestPki.delegated("CN=Known CA");
        unknown = OcspTestPki.delegated("CN=Unknown CA");
        service.putProfile(
                "known",
                known.pkcs12(),
                OcspTestPki.PASSWORD,
                null,
                null,
                known.certificate().getEncoded());
        service.setTimes(new OcspService.Times(Instant.parse("2029-01-01T00:00:00Z"), null));
        forwarder.answer =
                new OCSPRespBuilder().build(OCSPRespBuilder.SIG_REQUIRED, null).getEncoded();
    }

    private static byte[] request(final Ca... issuers) throws Exception {
        final List<CertificateID> ids = new ArrayList<>();
        for (final Ca issuer : issuers) {
            ids.add(OcspTestPki.certId(issuer.certificate(), BigInteger.TEN, "SHA-1"));
        }
        return OcspTestPki.request(ids);
    }

    private static int status(final byte[] response) throws IOException {
        return new OCSPResp(response).getStatus();
    }

    @Test
    void forwardingIsDisabledByDefault() throws Exception {
        assertThat(new OcspService(forwarder).forwarding())
                .isEqualTo(new OcspService.Forwarding(false, null));
        assertThat(status(service.respond(request(unknown))))
                .isEqualTo(OCSPRespBuilder.UNAUTHORIZED);
        assertThat(forwarder.targets).isEmpty();
    }

    @Test
    void requestWithoutProfileIsForwardedAndTheAnswerReturnedUnchanged() throws Exception {
        service.setForwarding(new OcspService.Forwarding(true, UPSTREAM));

        assertThat(service.respond(request(unknown))).isEqualTo(forwarder.answer);
        assertThat(forwarder.targets).containsExactly(URI.create(UPSTREAM));
    }

    @Test
    void requestWithProfileIsAnsweredLocallyEvenWhenForwardingIsEnabled() throws Exception {
        service.setForwarding(new OcspService.Forwarding(true, UPSTREAM));

        assertThat(status(service.respond(request(known)))).isEqualTo(OCSPRespBuilder.SUCCESSFUL);
        assertThat(forwarder.targets).isEmpty();
    }

    @Test
    void mixedRequestWithOneKnownIssuerIsNotForwarded() throws Exception {
        service.setForwarding(new OcspService.Forwarding(true, UPSTREAM));

        assertThat(status(service.respond(request(known, unknown))))
                .isEqualTo(OCSPRespBuilder.UNAUTHORIZED);
        assertThat(forwarder.targets).isEmpty();
    }

    @Test
    void alreadyForwardedRequestIsNeverForwardedAgain() throws Exception {
        service.setForwarding(new OcspService.Forwarding(true, UPSTREAM));

        assertThat(status(service.respond(request(unknown), true)))
                .isEqualTo(OCSPRespBuilder.UNAUTHORIZED);
        assertThat(forwarder.targets).isEmpty();
    }

    @Test
    void malformedRequestIsNotForwarded() throws Exception {
        service.setForwarding(new OcspService.Forwarding(true, UPSTREAM));

        assertThat(status(service.respond(new byte[] {1, 2, 3})))
                .isEqualTo(OCSPRespBuilder.MALFORMED_REQUEST);
        assertThat(forwarder.targets).isEmpty();
    }

    @Test
    void failedForwardAnswersTryLater() throws Exception {
        service.setForwarding(new OcspService.Forwarding(true, UPSTREAM));
        forwarder.failure = new IOException("connection refused");

        assertThat(status(service.respond(request(unknown)))).isEqualTo(OCSPRespBuilder.TRY_LATER);
    }

    @Test
    void nonOcspAnswerOfTheUpstreamAnswersTryLater() throws Exception {
        service.setForwarding(new OcspService.Forwarding(true, UPSTREAM));
        forwarder.answer =
                "<html>not ocsp</html>".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        assertThat(status(service.respond(request(unknown)))).isEqualTo(OCSPRespBuilder.TRY_LATER);
    }

    @Test
    void disablingKeepsTheUrlAndStopsForwarding() throws Exception {
        service.setForwarding(new OcspService.Forwarding(true, UPSTREAM));
        service.setForwarding(new OcspService.Forwarding(false, " " + UPSTREAM + " "));

        assertThat(service.forwarding()).isEqualTo(new OcspService.Forwarding(false, UPSTREAM));
        assertThat(status(service.respond(request(unknown))))
                .isEqualTo(OCSPRespBuilder.UNAUTHORIZED);
        assertThat(forwarder.targets).isEmpty();
    }

    @Test
    void disabledWithoutUrlIsAccepted() {
        service.setForwarding(new OcspService.Forwarding(false, "  "));

        assertThat(service.forwarding()).isEqualTo(new OcspService.Forwarding(false, null));
    }

    @Test
    void rejectsMissingSettingsAndEnabledWithoutUrl() {
        assertThatThrownBy(() -> service.setForwarding(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.setForwarding(new OcspService.Forwarding(true, null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("URL is required");
        assertThat(service.forwarding().enabled()).isFalse();
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "ftp://host/ocsp",
                "/relative/ocsp",
                "host/ocsp",
                "http://",
                "http://host/ocsp#frag",
                "http://ho st/ocsp"
            })
    void rejectsInvalidUrls(final String url) {
        assertThatThrownBy(() -> service.setForwarding(new OcspService.Forwarding(true, url)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(service.forwarding()).isEqualTo(new OcspService.Forwarding(false, null));
    }

    @Test
    void acceptsHttpsUrlWithPortAndQuery() {
        service.setForwarding(new OcspService.Forwarding(true, "HTTPS://ocsp.example:8443/a?b=c"));

        assertThat(service.forwarding().url()).isEqualTo("HTTPS://ocsp.example:8443/a?b=c");
    }
}
