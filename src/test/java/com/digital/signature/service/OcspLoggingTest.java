package com.digital.signature.service;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.digital.signature.util.OcspTestPki;
import com.digital.signature.util.OcspTestPki.Ca;
import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

/** Checks that every OCSP outcome and configuration change leaves a useful log message. */
class OcspLoggingTest {
    private static final Instant SIMULATED = Instant.parse("2029-01-01T00:00:00Z");
    private final Logger logger = (Logger) LoggerFactory.getLogger(OcspService.class);
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    private OcspService service;
    private Ca ca;

    @BeforeEach
    void setUp() throws Exception {
        logger.setLevel(Level.DEBUG);
        appender.start();
        logger.addAppender(appender);
        service = new OcspService();
        ca = OcspTestPki.delegated("CN=Logging CA");
        service.putProfile(
                "logca",
                ca.pkcs12(),
                OcspTestPki.PASSWORD,
                null,
                null,
                ca.certificate().getEncoded());
        service.setTimes(new OcspService.Times(SIMULATED, null));
        appender.list.clear();
    }

    @AfterEach
    void tearDown() {
        logger.detachAppender(appender);
        logger.setLevel(null);
    }

    private byte[] request(final Ca issuer, final long... serials) throws Exception {
        final List<org.bouncycastle.cert.ocsp.CertificateID> ids =
                java.util.Arrays.stream(serials)
                        .mapToObj(
                                s -> {
                                    try {
                                        return OcspTestPki.certId(
                                                issuer.certificate(),
                                                BigInteger.valueOf(s),
                                                "SHA-1");
                                    } catch (Exception e) {
                                        throw new IllegalStateException(e);
                                    }
                                })
                        .toList();
        return OcspTestPki.request(ids);
    }

    private List<String> messages(final Level level) {
        return appender.list.stream()
                .filter(e -> e.getLevel() == level)
                .map(ILoggingEvent::getFormattedMessage)
                .toList();
    }

    @Test
    void successfulResponseIsLoggedWithProfileTimesAndStatuses() throws Exception {
        service.putStatus(
                "logca",
                "11",
                new OcspService.StatusEntry(null, "REVOKED", SIMULATED.minusSeconds(60), 1));
        appender.list.clear();

        service.respond(request(ca, 0x11, 0x12));

        assertThat(messages(Level.INFO))
                .singleElement()
                .asString()
                .contains("OCSP response successful", "profile 'logca'", "thisUpdate=" + SIMULATED)
                .contains("11=REVOKED at", "12=GOOD (default)");
        assertThat(messages(Level.DEBUG)).anyMatch(m -> m.contains("serial=11 hash=SHA-1"));
    }

    @Test
    void unauthorizedForUnknownIssuerLogsRequestedAndExpectedHashes() throws Exception {
        final Ca other = OcspTestPki.delegated("CN=Other CA");

        final OCSPResp response = new OCSPResp(service.respond(request(other, 5)));

        assertThat(response.getStatus()).isEqualTo(OCSPRespBuilder.UNAUTHORIZED);
        assertThat(messages(Level.WARN))
                .singleElement()
                .asString()
                .contains("OCSP response unauthorized", "no issuer profile matches serial=5")
                .contains("issuerNameHash=", "profile 'logca'", "expects", "different issuer");
    }

    @Test
    void unauthorizedForSameNameDifferentKeyExplainsTheKeyMismatch() throws Exception {
        final Ca sameName = OcspTestPki.delegated("CN=Logging CA");

        service.respond(request(sameName, 5));

        assertThat(messages(Level.WARN))
                .singleElement()
                .asString()
                .contains("same issuer name but different key");
    }

    @Test
    void unauthorizedWithoutProfilesSaysNothingIsConfigured() throws Exception {
        service.deleteProfile("logca");
        appender.list.clear();

        service.respond(request(ca, 5));

        assertThat(messages(Level.WARN))
                .singleElement()
                .asString()
                .contains("no OCSP issuer profile is configured");
    }

    @Test
    void unauthorizedForMixedIssuersNamesBothProfiles() throws Exception {
        final Ca second = OcspTestPki.delegated("CN=Second CA");
        service.putProfile(
                "second",
                second.pkcs12(),
                OcspTestPki.PASSWORD,
                null,
                null,
                second.certificate().getEncoded());
        appender.list.clear();
        final List<org.bouncycastle.cert.ocsp.CertificateID> ids =
                List.of(
                        OcspTestPki.certId(ca.certificate(), BigInteger.ONE, "SHA-1"),
                        OcspTestPki.certId(second.certificate(), BigInteger.TWO, "SHA-1"));

        service.respond(OcspTestPki.request(ids));

        assertThat(messages(Level.WARN))
                .singleElement()
                .asString()
                .contains("mixes issuers", "'logca'", "'second'");
    }

    @Test
    void malformedRequestsLogTheReason() {
        service.respond(null);
        service.respond(new byte[] {1, 2, 3});
        service.respond(new byte[70_000]);

        assertThat(messages(Level.WARN))
                .hasSize(3)
                .allMatch(m -> m.startsWith("OCSP response malformedRequest"))
                .anyMatch(m -> m.contains("the request is empty"))
                .anyMatch(m -> m.contains("not a DER encoded OCSPRequest"))
                .anyMatch(m -> m.contains("too large"));
    }

    @Test
    void signerNotValidAtSimulatedTimeIsLoggedAsInternalErrorReason() throws Exception {
        service.setTimes(new OcspService.Times(Instant.parse("2035-01-01T00:00:00Z"), null));
        appender.list.clear();

        final OCSPResp response = new OCSPResp(service.respond(request(ca, 5)));

        assertThat(response.getStatus()).isEqualTo(OCSPRespBuilder.INTERNAL_ERROR);
        assertThat(messages(Level.WARN))
                .singleElement()
                .asString()
                .contains("internalError for profile 'logca'", "signer certificate")
                .contains("not valid at thisUpdate 2035-01-01T00:00:00Z");
    }

    @Test
    void revocationAfterThisUpdateIsWarnedOnConfigurationAndOnRequest() throws Exception {
        service.putStatus(
                "logca",
                "21",
                new OcspService.StatusEntry(null, "REVOKED", SIMULATED.plusSeconds(60), null));
        assertThat(messages(Level.WARN))
                .singleElement()
                .asString()
                .contains("serial 21", "after the simulated thisUpdate");
        appender.list.clear();

        service.respond(request(ca, 0x21));

        assertThat(messages(Level.WARN))
                .singleElement()
                .asString()
                .contains("internalError", "serial 21 is revoked at", "after thisUpdate");
    }

    @Test
    void configurationChangesAreLoggedAtInfo() throws Exception {
        service.putStatus("logca", "aa", new OcspService.StatusEntry(null, "UNKNOWN", null, null));
        service.deleteStatus("logca", "aa");
        service.setTimes(new OcspService.Times(null, null));
        service.addCustomPath("/ca/ocsp");
        service.removeCustomPath("/ca/ocsp");
        service.putProfile(
                "logca",
                ca.pkcs12(),
                OcspTestPki.PASSWORD,
                null,
                null,
                ca.certificate().getEncoded());
        service.deleteProfile("logca");

        assertThat(messages(Level.INFO))
                .anyMatch(m -> m.contains("serial AA in profile 'logca' set to UNKNOWN"))
                .anyMatch(m -> m.contains("serial aa in profile 'logca' removed"))
                .anyMatch(m -> m.contains("thisUpdate=current time"))
                .anyMatch(m -> m.contains("serves custom path /ca/ocsp"))
                .anyMatch(m -> m.contains("custom path /ca/ocsp removed"))
                .anyMatch(m -> m.contains("profile 'logca' stored (same CA"))
                .anyMatch(m -> m.contains("profile 'logca' deleted"));
    }

    @Test
    void failedConfigurationChangesDoNotLogSuccess() {
        try {
            service.putStatus("logca", "zz", new OcspService.StatusEntry(null, "GOOD", null, null));
        } catch (IllegalArgumentException expected) {
            // The controller logs rejected admin calls; the service must not log a change.
        }
        assertThat(appender.list).isEmpty();
    }
}
