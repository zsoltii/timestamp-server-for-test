package com.digital.signature.cucumber.steps;

import static org.assertj.core.api.Assertions.assertThat;

import com.digital.signature.service.OcspService;
import com.digital.signature.util.OcspTestPki;
import com.digital.signature.util.OcspTestPki.Ca;
import io.cucumber.java.After;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;

/** Step definitions that drive the OCSP responder of the running server over HTTP. */
public class OcspStepDefinitions {
    private static final Map<String, Integer> OCSP_STATUSES =
            Map.of(
                    "successful", OCSPRespBuilder.SUCCESSFUL,
                    "malformedRequest", OCSPRespBuilder.MALFORMED_REQUEST,
                    "internalError", OCSPRespBuilder.INTERNAL_ERROR,
                    "unauthorized", OCSPRespBuilder.UNAUTHORIZED,
                    "tryLater", OCSPRespBuilder.TRY_LATER,
                    "sigRequired", OCSPRespBuilder.SIG_REQUIRED);

    private final Environment environment;
    private final OcspService ocspService;
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private static final String DEFAULT_RESPONDER_PATH = "/api/ocsp/responder";
    private String responderPath = DEFAULT_RESPONDER_PATH;
    private final Map<String, Ca> cas = new HashMap<>();
    private HttpResponse<byte[]> adminResponse;
    private OCSPResp ocspResponse;
    private com.sun.net.httpserver.HttpServer upstream;
    private final java.util.concurrent.atomic.AtomicInteger upstreamCalls =
            new java.util.concurrent.atomic.AtomicInteger();

    @Autowired
    public OcspStepDefinitions(final Environment environment, final OcspService ocspService) {
        this.environment = environment;
        this.ocspService = ocspService;
    }

    /** The server is shared between scenarios, so OCSP profiles and times must not leak. */
    @After
    public void resetOcsp() {
        ocspService.profiles().forEach(profile -> ocspService.deleteProfile(profile.id()));
        ocspService.setTimes(new OcspService.Times(null, null));
        ocspService.customPaths().forEach(ocspService::removeCustomPath);
        ocspService.setForwarding(new OcspService.Forwarding(false, null));
        if (upstream != null) {
            upstream.stop(0);
            upstream = null;
        }
    }

    @Given("an upstream OCSP responder answering {string}")
    public void anUpstreamOcspResponderAnswering(final String status) throws Exception {
        final byte[] answer =
                new OCSPRespBuilder().build(OCSP_STATUSES.get(status), null).getEncoded();
        upstream =
                com.sun.net.httpserver.HttpServer.create(
                        new java.net.InetSocketAddress("127.0.0.1", 0), 0);
        upstream.createContext(
                "/upstream/ocsp",
                exchange -> {
                    upstreamCalls.incrementAndGet();
                    exchange.getRequestBody().readAllBytes();
                    exchange.getResponseHeaders().add("Content-Type", "application/ocsp-response");
                    exchange.sendResponseHeaders(200, answer.length);
                    try (java.io.OutputStream out = exchange.getResponseBody()) {
                        out.write(answer);
                    }
                });
        upstream.start();
    }

    @Given("OCSP forwarding is enabled to the upstream responder")
    public void forwardingEnabledToUpstream() throws Exception {
        putForwarding(
                true, "http://127.0.0.1:" + upstream.getAddress().getPort() + "/upstream/ocsp");
        assertThat(adminResponse.statusCode()).isEqualTo(204);
    }

    @Given("OCSP forwarding is enabled to this server's own responder")
    public void forwardingEnabledToItself() throws Exception {
        putForwarding(true, uri("/api/ocsp/responder").toString());
        assertThat(adminResponse.statusCode()).isEqualTo(204);
    }

    @Given("OCSP forwarding is disabled with the upstream URL kept")
    public void forwardingDisabled() throws Exception {
        putForwarding(
                false, "http://127.0.0.1:" + upstream.getAddress().getPort() + "/upstream/ocsp");
        assertThat(adminResponse.statusCode()).isEqualTo(204);
    }

    @When("I enable OCSP forwarding without URL")
    public void iEnableForwardingWithoutUrl() throws Exception {
        putForwarding(true, null);
    }

    @Then("the upstream OCSP responder received {int} request(s)")
    public void theUpstreamReceived(final int count) {
        assertThat(upstreamCalls.get()).isEqualTo(count);
    }

    private void putForwarding(final boolean enabled, final String url) throws Exception {
        adminResponse =
                send(
                        HttpRequest.newBuilder(uri("/api/ocsp/forwarding"))
                                .header("Content-Type", "application/json")
                                .PUT(
                                        HttpRequest.BodyPublishers.ofString(
                                                "{\"enabled\":"
                                                        + enabled
                                                        + ",\"url\":"
                                                        + (url == null ? "null" : "\"" + url + "\"")
                                                        + "}"))
                                .build());
    }

    @Given("the OCSP simulated time is {string}")
    public void theOcspSimulatedTimeIs(final String time) throws Exception {
        final HttpRequest request =
                HttpRequest.newBuilder(uri("/api/ocsp/times"))
                        .header("Content-Type", "application/json")
                        .PUT(
                                HttpRequest.BodyPublishers.ofString(
                                        "{\"thisUpdate\":\"" + time + "\"}"))
                        .build();
        assertThat(send(request).statusCode()).isEqualTo(204);
    }

    @Given("OCSP CA {string} with subject {string} is uploaded as profile {string}")
    public void delegatedCaIsUploaded(final String alias, final String subject, final String id)
            throws Exception {
        uploadNew(alias, OcspTestPki.delegated(subject), id);
    }

    @Given(
            "OCSP CA {string} with subject {string} signing directly is uploaded as profile {string}")
    public void directCaIsUploaded(final String alias, final String subject, final String id)
            throws Exception {
        uploadNew(alias, OcspTestPki.direct(subject), id);
    }

    @Given(
            "OCSP CA {string} with subject {string} valid until {string} is uploaded as profile"
                    + " {string}")
    public void caValidUntilIsUploaded(
            final String alias, final String subject, final String until, final String id)
            throws Exception {
        uploadNew(
                alias,
                OcspTestPki.create(subject, true, OcspTestPki.DEFAULT_FROM, Instant.parse(until)),
                id);
    }

    @When("OCSP CA {string} is uploaded as profile {string}")
    public void existingCaIsUploaded(final String alias, final String id) throws Exception {
        final Ca ca = cas.get(alias);
        upload(id, ca.pkcs12(), ca.certificate().getEncoded());
    }

    @When("OCSP CA {string} renewed with the same name and key is uploaded as profile {string}")
    public void renewedCaIsUploaded(final String alias, final String id) throws Exception {
        final Ca renewed = renew(alias);
        upload(id, renewed.pkcs12(), renewed.certificate().getEncoded());
        if (adminResponse.statusCode() == 204) {
            cas.put(alias, renewed);
        }
    }

    @When(
            "OCSP CA {string} renewed with the old CA certificate in the PKCS12 is uploaded as"
                    + " profile {string}")
    public void renewedCaWithOldPkcs12IsUploaded(final String alias, final String id)
            throws Exception {
        upload(id, cas.get(alias).pkcs12(), renew(alias).certificate().getEncoded());
    }

    @Given("certificate serial {string} of OCSP profile {string} is GOOD")
    public void serialIsGood(final String serial, final String id) throws Exception {
        putStatus(id, serial, "{\"status\":\"GOOD\"}");
    }

    @Given(
            "certificate serial {string} of OCSP profile {string} is REVOKED at {string} with reason {int}")
    public void serialIsRevoked(
            final String serial, final String id, final String time, final int reason)
            throws Exception {
        putStatus(
                id,
                serial,
                "{\"status\":\"REVOKED\",\"revocationTime\":\""
                        + time
                        + "\",\"reason\":"
                        + reason
                        + "}");
    }

    @Given("the OCSP custom path {string} is registered")
    public void customPathIsRegistered(final String path) throws Exception {
        registerPath(path);
        assertThat(adminResponse.statusCode()).isEqualTo(201);
    }

    @When("I register the OCSP custom path {string}")
    public void iRegisterCustomPath(final String path) throws Exception {
        registerPath(path);
    }

    @When(
            "I send an OCSP {word} request for serial {string} issued by OCSP CA {string} on path {string}")
    public void iSendAnOcspRequestOnPath(
            final String method, final String serial, final String alias, final String path)
            throws Exception {
        responderPath = path;
        try {
            iSendAnOcspRequest(method, serial, alias);
        } finally {
            responderPath = DEFAULT_RESPONDER_PATH;
        }
    }

    private void registerPath(final String path) throws Exception {
        adminResponse =
                send(
                        HttpRequest.newBuilder(uri("/api/ocsp/paths"))
                                .header("Content-Type", "application/json")
                                .POST(
                                        HttpRequest.BodyPublishers.ofString(
                                                "{\"path\":\"" + path + "\"}"))
                                .build());
    }

    @When("I send an OCSP {word} request for serial {string} issued by OCSP CA {string}")
    public void iSendAnOcspRequest(final String method, final String serial, final String alias)
            throws Exception {
        final List<CertificateID> ids = List.of(certId(alias, serial, "SHA-1"));
        if ("GET".equals(method)) {
            sendGet(ids);
        } else {
            sendPost(OcspTestPki.request(ids));
        }
    }

    @When(
            "I send an OCSP POST request for serial {string} issued by OCSP CA {string} using {string}")
    public void iSendAnOcspRequestUsingHash(
            final String serial, final String alias, final String hash) throws Exception {
        sendPost(OcspTestPki.request(List.of(certId(alias, serial, hash))));
    }

    @When(
            "I send an OCSP POST request for serials {string} and {string} issued by OCSP CA {string}")
    public void iSendAnOcspRequestForTwoSerials(
            final String first, final String second, final String alias) throws Exception {
        sendPost(
                OcspTestPki.request(
                        List.of(certId(alias, first, "SHA-1"), certId(alias, second, "SHA-1"))));
    }

    @When(
            "I send an OCSP POST request for serial {string} issued by OCSP CA {string} and serial"
                    + " {string} issued by OCSP CA {string}")
    public void iSendAMixedOcspRequest(
            final String first, final String firstAlias, final String second, final String alias)
            throws Exception {
        sendPost(
                OcspTestPki.request(
                        List.of(
                                certId(firstAlias, first, "SHA-1"),
                                certId(alias, second, "SHA-1"))));
    }

    @When("I send an OCSP POST request for serial {string} issued by an unknown CA")
    public void iSendAnOcspRequestForAnUnknownCa(final String serial) throws Exception {
        final Ca unknown = OcspTestPki.delegated("CN=Unknown CA " + UUID.randomUUID());
        sendPost(
                OcspTestPki.request(
                        List.of(
                                OcspTestPki.certId(
                                        unknown.certificate(),
                                        new BigInteger(serial, 16),
                                        "SHA-1"))));
    }

    @Then("the OCSP response status is {string}")
    public void theOcspResponseStatusIs(final String status) {
        assertThat(OCSP_STATUSES).containsKey(status);
        assertThat(ocspResponse.getStatus()).isEqualTo(OCSP_STATUSES.get(status));
    }

    @Then("the OCSP certificate status is {string}")
    public void theOcspCertificateStatusIs(final String expected) throws Exception {
        final CertificateStatus status = basic().getResponses()[0].getCertStatus();
        final String actual =
                status == CertificateStatus.GOOD
                        ? "GOOD"
                        : status instanceof RevokedStatus
                                ? "REVOKED"
                                : status instanceof UnknownStatus ? "UNKNOWN" : "OTHER";
        assertThat(actual).isEqualTo(expected);
    }

    @Then("the OCSP certificate status of response {int} is {string}")
    public void theOcspCertificateStatusOfResponseIs(final int position, final String expected)
            throws Exception {
        final CertificateStatus status = basic().getResponses()[position - 1].getCertStatus();
        final String actual =
                status == CertificateStatus.GOOD
                        ? "GOOD"
                        : status instanceof RevokedStatus
                                ? "REVOKED"
                                : status instanceof UnknownStatus ? "UNKNOWN" : "OTHER";
        assertThat(actual).isEqualTo(expected);
    }

    @Given("certificate serial {string} of OCSP profile {string} is UNKNOWN")
    public void serialIsUnknown(final String serial, final String id) throws Exception {
        putStatus(id, serial, "{\"status\":\"UNKNOWN\"}");
    }

    @When("the configured status of serial {string} of OCSP profile {string} is removed")
    public void configuredStatusIsRemoved(final String serial, final String id) throws Exception {
        adminResponse =
                send(
                        HttpRequest.newBuilder(
                                        uri("/api/ocsp/profiles/" + id + "/statuses/" + serial))
                                .DELETE()
                                .build());
    }

    @Then("the OCSP response is signed by the signer of OCSP CA {string}")
    public void theOcspResponseIsSignedBy(final String alias) throws Exception {
        assertThat(
                        basic().isSignatureValid(
                                        new JcaContentVerifierProviderBuilder()
                                                .build(cas.get(alias).signer().getPublicKey())))
                .isTrue();
    }

    @Then("the OCSP response contains {int} certificate statuses")
    public void theOcspResponseContainsStatuses(final int count) throws Exception {
        assertThat(basic().getResponses()).hasSize(count);
    }

    @Then("the OCSP admin response status is {int}")
    public void theOcspAdminResponseStatusIs(final int status) {
        assertThat(adminResponse.statusCode()).isEqualTo(status);
    }

    @Then("the OCSP admin response body contains {string}")
    public void theOcspAdminResponseBodyContains(final String text) {
        assertThat(new String(adminResponse.body(), StandardCharsets.UTF_8)).contains(text);
    }

    @Then("the OCSP profile list contains only {string}")
    public void theOcspProfileListContainsOnly(final String id) throws Exception {
        final String body =
                new String(
                        send(HttpRequest.newBuilder(uri("/api/ocsp/profiles")).GET().build())
                                .body(),
                        StandardCharsets.UTF_8);
        assertThat(body).contains("\"id\":\"" + id + "\"");
        assertThat(body.split("\"id\":", -1)).hasSize(2);
    }

    @Then("OCSP profile {string} has {int} configured statuses")
    public void ocspProfileHasStatuses(final String id, final int count) throws Exception {
        final String body =
                new String(
                        send(HttpRequest.newBuilder(uri("/api/ocsp/profiles/" + id + "/statuses"))
                                        .GET()
                                        .build())
                                .body(),
                        StandardCharsets.UTF_8);
        assertThat(body.split("\"serialNumber\":", -1)).hasSize(count + 1);
    }

    private void uploadNew(final String alias, final Ca ca, final String id) throws Exception {
        cas.put(alias, ca);
        upload(id, ca.pkcs12(), ca.certificate().getEncoded());
        assertThat(adminResponse.statusCode()).isEqualTo(204);
    }

    private Ca renew(final String alias) throws Exception {
        return cas.get(alias)
                .renew(OcspTestPki.DEFAULT_FROM, Instant.parse("2031-01-01T00:00:00Z"));
    }

    private void upload(final String id, final byte[] pkcs12, final byte[] issuer)
            throws Exception {
        final String boundary = "ocsp-" + UUID.randomUUID();
        final ByteArrayOutputStream body = new ByteArrayOutputStream();
        filePart(body, boundary, "file", "signer.p12", pkcs12);
        filePart(body, boundary, "issuer", "issuer.der", issuer);
        body.writeBytes(
                ("--"
                                + boundary
                                + "\r\nContent-Disposition: form-data; name=\"keystorePassword\""
                                + "\r\n\r\n"
                                + OcspTestPki.PASSWORD
                                + "\r\n--"
                                + boundary
                                + "--\r\n")
                        .getBytes(StandardCharsets.UTF_8));
        adminResponse =
                send(
                        HttpRequest.newBuilder(uri("/api/ocsp/profiles/" + id))
                                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                                .PUT(HttpRequest.BodyPublishers.ofByteArray(body.toByteArray()))
                                .build());
    }

    private static void filePart(
            final ByteArrayOutputStream body,
            final String boundary,
            final String name,
            final String filename,
            final byte[] content) {
        body.writeBytes(
                ("--"
                                + boundary
                                + "\r\nContent-Disposition: form-data; name=\""
                                + name
                                + "\"; filename=\""
                                + filename
                                + "\"\r\nContent-Type: application/octet-stream\r\n\r\n")
                        .getBytes(StandardCharsets.UTF_8));
        body.writeBytes(content);
        body.writeBytes("\r\n".getBytes(StandardCharsets.UTF_8));
    }

    private void putStatus(final String id, final String serial, final String json)
            throws Exception {
        final HttpResponse<byte[]> result =
                send(
                        HttpRequest.newBuilder(
                                        uri("/api/ocsp/profiles/" + id + "/statuses/" + serial))
                                .header("Content-Type", "application/json")
                                .PUT(HttpRequest.BodyPublishers.ofString(json))
                                .build());
        assertThat(result.statusCode()).isEqualTo(204);
    }

    private CertificateID certId(final String alias, final String serial, final String hash)
            throws Exception {
        return OcspTestPki.certId(cas.get(alias).certificate(), new BigInteger(serial, 16), hash);
    }

    private void sendPost(final byte[] request) throws Exception {
        final HttpResponse<byte[]> result =
                send(
                        HttpRequest.newBuilder(uri(responderPath))
                                .header("Content-Type", "application/ocsp-request")
                                .POST(HttpRequest.BodyPublishers.ofByteArray(request))
                                .build());
        assertThat(result.statusCode()).isEqualTo(200);
        ocspResponse = new OCSPResp(result.body());
    }

    /**
     * Varies the nonce until the Base64 form contains '//' and '+' to exercise Tomcat and Spring
     * Security URL handling for encoded single and double slashes.
     */
    private void sendGet(final List<CertificateID> ids) throws Exception {
        String encoded = null;
        for (int i = 0; i < 4096 && encoded == null; i++) {
            final String candidate =
                    Base64.getEncoder()
                            .encodeToString(
                                    OcspTestPki.request(
                                            ids,
                                            new byte[] {
                                                (byte) 0xff,
                                                (byte) 0xff,
                                                (byte) 0xff,
                                                (byte) (i >> 8),
                                                (byte) i
                                            }));
            if (candidate.contains("//") && candidate.contains("+")) {
                encoded = candidate;
            }
        }
        assertThat(encoded).as("Base64 request containing '//' and '+'").isNotNull();
        final HttpResponse<byte[]> result =
                send(
                        HttpRequest.newBuilder(
                                        uri(
                                                responderPath
                                                        + "/"
                                                        + URLEncoder.encode(
                                                                encoded, StandardCharsets.UTF_8)))
                                .GET()
                                .build());
        assertThat(result.statusCode()).isEqualTo(200);
        ocspResponse = new OCSPResp(result.body());
    }

    private BasicOCSPResp basic() throws Exception {
        return (BasicOCSPResp) ocspResponse.getResponseObject();
    }

    private HttpResponse<byte[]> send(final HttpRequest request) throws Exception {
        return httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
    }

    private URI uri(final String path) {
        return URI.create(
                "http://localhost:" + environment.getProperty("local.server.port") + path);
    }
}
