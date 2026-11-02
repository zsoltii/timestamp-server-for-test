package com.digital.signature.cucumber.steps;

import static org.assertj.core.api.Assertions.assertThat;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;

/** Step definitions that call the running timestamp server over HTTP. */
public class TimestampStepDefinitions {

    private final Environment environment;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    private HttpResponse<byte[]> response;

    @Autowired
    public TimestampStepDefinitions(final Environment environment) {
        this.environment = environment;
    }

    @Given("the timestamp server is running")
    public void theTimestampServerIsRunning() {
        assertThat(environment.getProperty("local.server.port", Integer.class)).isPositive();
    }

    @When("I send a GET request to {string}")
    public void iSendAGetRequestTo(final String path) throws Exception {
        final HttpRequest request = HttpRequest.newBuilder(uri(path)).GET().build();
        response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
    }

    @When("I send an RFC 3161 timestamp request for the text {string}")
    public void iSendAnRfc3161TimestampRequestForTheText(final String text) throws Exception {
        final TimeStampRequestGenerator generator = new TimeStampRequestGenerator();
        generator.setCertReq(true);
        final TimeStampRequest tsRequest =
                generator.generate(NISTObjectIdentifiers.id_sha256, sha256(text));
        final HttpRequest request =
                HttpRequest.newBuilder(uri("/api/timestamp"))
                        .header("Content-Type", "application/timestamp-query")
                        .POST(HttpRequest.BodyPublishers.ofByteArray(tsRequest.getEncoded()))
                        .build();
        response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
    }

    @Then("the response status is {int}")
    public void theResponseStatusIs(final int status) {
        assertThat(response.statusCode()).isEqualTo(status);
    }

    @Then("the response body is not empty")
    public void theResponseBodyIsNotEmpty() {
        assertThat(body()).isNotBlank();
    }

    @Then("the response body is a valid ISO-8601 instant")
    public void theResponseBodyIsAValidIso8601Instant() {
        final Instant instant = Instant.parse(body().trim());
        assertThat(instant).isCloseTo(Instant.now(), within60Seconds());
    }

    @Then("the response body is a unix time within {int} seconds of now")
    public void theResponseBodyIsAUnixTimeWithinSecondsOfNow(final int seconds) {
        final long unix = Long.parseLong(body().trim());
        assertThat(Math.abs(Instant.now().getEpochSecond() - unix)).isLessThanOrEqualTo(seconds);
    }

    @Then("the response body contains {string}")
    public void theResponseBodyContains(final String marker) {
        assertThat(body()).contains(marker);
    }

    @Then("the timestamp response is granted")
    public void theTimestampResponseIsGranted() throws Exception {
        final TimeStampResponse tsResponse = new TimeStampResponse(response.body());
        assertThat(tsResponse.getStatus()).isZero();
        assertThat(tsResponse.getTimeStampToken()).isNotNull();
    }

    @Then("the timestamp token matches the digest of {string}")
    public void theTimestampTokenMatchesTheDigestOf(final String text) throws Exception {
        final TimeStampResponse tsResponse = new TimeStampResponse(response.body());
        assertThat(tsResponse.getTimeStampToken().getTimeStampInfo().getMessageImprintDigest())
                .isEqualTo(sha256(text));
    }

    private URI uri(final String path) {
        return URI.create(
                "http://localhost:" + environment.getProperty("local.server.port") + path);
    }

    private String body() {
        return new String(response.body(), StandardCharsets.UTF_8);
    }

    private static byte[] sha256(final String text) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
    }

    private static org.assertj.core.data.TemporalUnitOffset within60Seconds() {
        return org.assertj.core.api.Assertions.within(60, ChronoUnit.SECONDS);
    }
}
