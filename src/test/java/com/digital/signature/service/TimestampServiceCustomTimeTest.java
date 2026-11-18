package com.digital.signature.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.digital.signature.AbstractTest;
import com.digital.signature.config.TimeStampConfig;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests (no Spring context) for the custom and fixed timestamp time handling of {@link
 * TimestampService}. Every behaviour has positive and negative cases.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TimestampServiceCustomTimeTest extends AbstractTest {

    private TimestampService timestampService;

    @BeforeAll
    void createService() {
        timestampService = new TimestampService(new TimeStampConfig());
        timestampService.init();
    }

    @AfterEach
    void clearFixedTime() {
        timestampService.updateFixedTime(null);
    }

    // ==================== parseTimestampTime() ====================

    @ParameterizedTest
    @CsvSource({
        "2020-01-31 14:30:00, 2020-01-31T14:30:00Z",
        "2020-01-31 14:30:00Z, 2020-01-31T14:30:00Z",
        "2020-01-31 14:30:00+0200, 2020-01-31T12:30:00Z",
        "2020-01-31 14:30:00+02:00, 2020-01-31T12:30:00Z",
        "2020-01-31 14:30:00+02, 2020-01-31T12:30:00Z",
        "2020-01-31 14:30:00-0530, 2020-01-31T20:00:00Z",
        "2020-01-31 14:30:00+14:00, 2020-01-31T00:30:00Z",
        "2020-01-31 14:30:00 +0200, 2020-01-31T12:30:00Z",
        "2020-01-31 14:30:00 0200, 2020-01-31T12:30:00Z",
        "2020-01-31T14:30:00Z, 2020-01-31T14:30:00Z",
        "2024-02-29 00:00:00, 2024-02-29T00:00:00Z",
        "2026-11-01T12:34:56CEST, 2026-11-01T10:34:56Z",
        "2026-11-01 12:34:56CEST, 2026-11-01T10:34:56Z",
        "2026-11-01 12:34:56 CEST, 2026-11-01T10:34:56Z",
        "2026-11-01 12:34:56CET, 2026-11-01T11:34:56Z",
        "2026-11-01 12:34:56cet, 2026-11-01T11:34:56Z",
        "2026-11-01 12:34:56UTC, 2026-11-01T12:34:56Z",
        "2026-11-01 12:34:56GMT, 2026-11-01T12:34:56Z",
        "2026-11-01 12:34:56WET, 2026-11-01T12:34:56Z",
        "2026-11-01 12:34:56WEST, 2026-11-01T11:34:56Z",
        "2026-11-01 12:34:56EET, 2026-11-01T10:34:56Z",
        "2026-11-01 12:34:56EEST, 2026-11-01T09:34:56Z",
        "2026-11-01 12:34:56Europe/Budapest, 2026-11-01T11:34:56Z",
        "2026-07-01 12:00:00 Europe/Budapest, 2026-07-01T10:00:00Z",
        "2026-07-01T12:00:00Europe/London, 2026-07-01T11:00:00Z",
        "2026-07-01 12:00:00 America/New_York, 2026-07-01T16:00:00Z",
        "2026-07-01 12:00:00UTC+02:00, 2026-07-01T10:00:00Z",
        "'  2099-12-31 23:59:59  ', 2099-12-31T23:59:59Z"
    })
    void parseTimestampTime_shouldParseTime_whenFormatIsValid(
            final String input, final String expected) {
        assertThat(timestampService.parseTimestampTime(input)).isEqualTo(Instant.parse(expected));
    }

    @ParameterizedTest
    @CsvSource(
            value = {"null", "''", "'   '"},
            nullValues = "null")
    void parseTimestampTime_shouldReturnCurrentTime_whenTimeIsBlank(final String input) {
        final Instant before = Instant.now();

        final Instant result = timestampService.parseTimestampTime(input);

        assertThat(result).isBetween(before, Instant.now());
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "yesterday",
                "2020-01-31",
                "2020-01-31 14:30",
                "20-01-31 14:30:00",
                "2020/01/31 14:30:00",
                "2020-01-31  14:30:00",
                "2020-02-30 14:30:00",
                "2023-02-29 14:30:00",
                "2020-13-01 14:30:00",
                "2020-01-31 25:30:00",
                "2020-01-31 14:60:00",
                "2020-01-31 14:30:00+2500",
                "2020-01-31 14:30:00+19:00",
                "2020-01-31 14:30:00+02:00 extra",
                "2020-01-31 14:30:00 extra",
                "2020-01-31 14:30:00CST",
                "2020-01-31 14:30:00 PST",
                "2020-01-31 14:30:00XYZ",
                "2020-01-31 14:30:00Mars/Olympus",
                "2020-01-31 14:30:00Europe/",
                "2020-01-31 14:30:00Europe/Budapest/Extra",
                "2020-01-31 14:30:00CEST+01:00",
                "2020-01-31 14:30:00CEST CET"
            })
    void parseTimestampTime_shouldThrowException_whenFormatIsInvalid(final String input) {
        assertThatThrownBy(() -> timestampService.parseTimestampTime(input))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid time");
    }

    @Test
    void parseTimestampTime_shouldUseDaylightSavingRules_whenZoneIsRegionId() {
        final Instant winter =
                timestampService.parseTimestampTime("2026-01-15 12:00:00 Europe/Budapest");
        final Instant summer =
                timestampService.parseTimestampTime("2026-07-15 12:00:00 Europe/Budapest");

        assertThat(winter).isEqualTo(Instant.parse("2026-01-15T11:00:00Z"));
        assertThat(summer).isEqualTo(Instant.parse("2026-07-15T10:00:00Z"));
    }

    @Test
    void parseTimestampTime_shouldUseFixedOffset_whenZoneIsAbbreviation() {
        // CEST always means +02:00, even in winter
        assertThat(timestampService.parseTimestampTime("2026-01-15 12:00:00 CEST"))
                .isEqualTo(Instant.parse("2026-01-15T10:00:00Z"));
    }

    @Test
    void parseTimestampTime_shouldThrowExceptionWithZoneName_whenZoneIsUnknown() {
        assertThatThrownBy(() -> timestampService.parseTimestampTime("2020-01-31 14:30:00XYZ"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid time")
                .hasMessageContaining("XYZ");
    }

    // ==================== updateFixedTime() / getFixedTime() ====================

    @Test
    void getFixedTime_shouldReturnNull_whenNothingIsSet() {
        assertThat(timestampService.getFixedTime()).isNull();
    }

    @Test
    void updateFixedTime_shouldStoreAndReturnTime_whenTimeIsValid() {
        final Instant result = timestampService.updateFixedTime("2020-01-31 14:30:00+0200");

        assertThat(result).isEqualTo(Instant.parse("2020-01-31T12:30:00Z"));
        assertThat(timestampService.getFixedTime())
                .isEqualTo(Instant.parse("2020-01-31T12:30:00Z"));
    }

    @Test
    void updateFixedTime_shouldAcceptZoneName_whenTimeHasZoneAbbreviation() {
        final Instant result = timestampService.updateFixedTime("2026-11-01T12:34:56CEST");

        assertThat(result).isEqualTo(Instant.parse("2026-11-01T10:34:56Z"));
        assertThat(timestampService.getFixedTime()).isEqualTo(result);
    }

    @Test
    void updateFixedTime_shouldReplacePreviousTime_whenCalledAgain() {
        timestampService.updateFixedTime("2001-09-09 01:46:40");

        timestampService.updateFixedTime("2099-12-31 23:59:59");

        assertThat(timestampService.getFixedTime())
                .isEqualTo(Instant.parse("2099-12-31T23:59:59Z"));
    }

    @ParameterizedTest
    @CsvSource(
            value = {"null", "''", "'   '"},
            nullValues = "null")
    void updateFixedTime_shouldClearFixedTime_whenTimeIsBlank(final String blank) {
        timestampService.updateFixedTime("2001-09-09 01:46:40");

        final Instant result = timestampService.updateFixedTime(blank);

        assertThat(result).isNull();
        assertThat(timestampService.getFixedTime()).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"not a time", "2020-01-31", "2020-01-31 14:30:00XYZ"})
    void updateFixedTime_shouldThrowExceptionAndKeepPreviousTime_whenTimeIsInvalid(
            final String invalid) {
        timestampService.updateFixedTime("2001-09-09 01:46:40");

        assertThatThrownBy(() -> timestampService.updateFixedTime(invalid))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid time");

        assertThat(timestampService.getFixedTime())
                .isEqualTo(Instant.parse("2001-09-09T01:46:40Z"));
    }

    @Test
    void updateFixedTime_shouldLeaveNoFixedTime_whenInvalidTimeIsGivenFirst() {
        assertThatThrownBy(() -> timestampService.updateFixedTime("garbage"))
                .isInstanceOf(IllegalArgumentException.class);

        assertThat(timestampService.getFixedTime()).isNull();
    }

    // ==================== generateTimestampResponse(bytes, Instant) ====================

    @ParameterizedTest
    @ValueSource(strings = {"1970-01-01T00:00:01Z", "1999-12-31T23:59:59Z", "2099-01-01T00:00:00Z"})
    void generateTimestampResponse_shouldStampGivenTime_whenTimeIsPastOrFuture(final String time)
            throws Exception {
        final Instant expected = Instant.parse(time);

        final byte[] result =
                timestampService.generateTimestampResponse(request().getEncoded(), expected);

        final TimeStampResponse response = new TimeStampResponse(result);
        assertThat(response.getStatus()).isZero();
        assertThat(tokenTime(result)).isEqualTo(expected);
    }

    @Test
    void generateTimestampResponse_shouldKeepDigest_whenTimeIsGiven() throws Exception {
        final byte[] result =
                timestampService.generateTimestampResponse(
                        request().getEncoded(), Instant.parse("2001-09-09T01:46:40Z"));

        assertThat(
                        new TimeStampResponse(result)
                                .getTimeStampToken()
                                .getTimeStampInfo()
                                .getMessageImprintDigest())
                .isEqualTo(sha256());
    }

    @Test
    void generateTimestampResponse_shouldThrowException_whenGivenTimeIsNull() throws Exception {
        final byte[] requestBytes = request().getEncoded();

        assertThatThrownBy(() -> timestampService.generateTimestampResponse(requestBytes, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Timestamp time cannot be null");
    }

    @Test
    void generateTimestampResponse_shouldThrowException_whenRequestIsNullAndTimeIsGiven() {
        final Instant time = Instant.parse("2001-09-09T01:46:40Z");

        assertThatThrownBy(() -> timestampService.generateTimestampResponse(null, time))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Request bytes cannot be null");
    }

    @Test
    void generateTimestampResponse_shouldThrowException_whenRequestIsGarbageAndTimeIsGiven() {
        final byte[] garbage = "invalid-garbage-data".getBytes();
        final Instant time = Instant.parse("2001-09-09T01:46:40Z");

        assertThatThrownBy(() -> timestampService.generateTimestampResponse(garbage, time))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Failed to generate timestamp response");
    }

    @Test
    void generateTimestampResponse_shouldReturnRejection_whenAlgorithmIsNotAcceptedAndTimeIsGiven()
            throws Exception {
        final byte[] md5Hash = MessageDigest.getInstance("MD5").digest("test-data".getBytes());
        final TimeStampRequest md5Request =
                new TimeStampRequestGenerator()
                        .generate(PKCSObjectIdentifiers.md5, md5Hash, BigInteger.ONE);

        final byte[] result =
                timestampService.generateTimestampResponse(
                        md5Request.getEncoded(), Instant.parse("2001-09-09T01:46:40Z"));

        final TimeStampResponse response = new TimeStampResponse(result);
        assertThat(response.getStatus()).isNotZero();
        assertThat(response.getTimeStampToken()).isNull();
    }

    // ==================== generateTimestampResponse(bytes) ====================

    @Test
    void generateTimestampResponse_shouldStampCurrentTime_whenNoFixedTimeIsSet() throws Exception {
        final Instant before = Instant.now().truncatedTo(ChronoUnit.SECONDS);

        final byte[] result = timestampService.generateTimestampResponse(request().getEncoded());

        assertThat(tokenTime(result)).isBetween(before, Instant.now());
    }

    @Test
    void generateTimestampResponse_shouldStampFixedTime_whenFixedTimeIsSet() throws Exception {
        timestampService.updateFixedTime("2001-09-09 03:46:40+0200");

        final byte[] result = timestampService.generateTimestampResponse(request().getEncoded());

        assertThat(new TimeStampResponse(result).getStatus()).isZero();
        assertThat(tokenTime(result)).isEqualTo(Instant.parse("2001-09-09T01:46:40Z"));
    }

    @Test
    void generateTimestampResponse_shouldStampSameTime_whenCalledRepeatedlyWithFixedTime()
            throws Exception {
        timestampService.updateFixedTime("2099-12-31 23:59:59");

        final Instant first =
                tokenTime(timestampService.generateTimestampResponse(request().getEncoded()));
        final Instant second =
                tokenTime(timestampService.generateTimestampResponse(request().getEncoded()));

        assertThat(first).isEqualTo(second).isEqualTo(Instant.parse("2099-12-31T23:59:59Z"));
    }

    @Test
    void generateTimestampResponse_shouldStampCurrentTime_whenFixedTimeIsCleared()
            throws Exception {
        timestampService.updateFixedTime("2001-09-09 01:46:40");
        timestampService.updateFixedTime("");
        final Instant before = Instant.now().truncatedTo(ChronoUnit.SECONDS);

        final byte[] result = timestampService.generateTimestampResponse(request().getEncoded());

        assertThat(tokenTime(result)).isBetween(before, Instant.now());
    }

    @Test
    void generateTimestampResponse_shouldPreferExplicitTime_whenFixedTimeIsSet() throws Exception {
        timestampService.updateFixedTime("2001-09-09 01:46:40");
        final Instant explicit = Instant.parse("1999-12-31T23:59:59Z");

        final byte[] result =
                timestampService.generateTimestampResponse(request().getEncoded(), explicit);

        assertThat(tokenTime(result)).isEqualTo(explicit);
    }

    @Test
    void generateTimestampResponse_shouldThrowException_whenRequestIsNullAndFixedTimeIsSet() {
        timestampService.updateFixedTime("2001-09-09 01:46:40");

        assertThatThrownBy(() -> timestampService.generateTimestampResponse(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Request bytes cannot be null");
    }

    @Test
    void generateTimestampResponse_shouldThrowException_whenRequestIsGarbageAndFixedTimeIsSet() {
        timestampService.updateFixedTime("2001-09-09 01:46:40");
        final byte[] garbage = "invalid-garbage-data".getBytes();

        assertThatThrownBy(() -> timestampService.generateTimestampResponse(garbage))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Failed to generate timestamp response");
    }

    // ==================== logging ====================

    @Test
    void generateTimestampResponse_shouldLogUsedTime_whenResponseIsGenerated() throws Exception {
        timestampService.generateTimestampResponse(
                request().getEncoded(), Instant.parse("2001-09-09T01:46:40Z"));

        assertThat(getLoggedEvents())
                .anyMatch(
                        event ->
                                event.getFormattedMessage()
                                        .contains(
                                                "Generating timestamp with time:"
                                                        + " 2001-09-09T01:46:40Z"));
    }

    @Test
    void generateTimestampResponse_shouldNotLogTime_whenRequestIsInvalid() {
        final byte[] garbage = "invalid-garbage-data".getBytes();

        assertThatThrownBy(
                        () ->
                                timestampService.generateTimestampResponse(
                                        garbage, Instant.parse("2001-09-09T01:46:40Z")))
                .isInstanceOf(IllegalStateException.class);

        assertThat(getLoggedEvents())
                .noneMatch(
                        event -> event.getFormattedMessage().contains("Generating timestamp with"));
    }

    // ==================== helpers ====================

    private static TimeStampRequest request() throws Exception {
        return new TimeStampRequestGenerator()
                .generate(NISTObjectIdentifiers.id_sha256, sha256(), BigInteger.valueOf(100));
    }

    private static byte[] sha256() throws Exception {
        return MessageDigest.getInstance("SHA-256").digest("test-data".getBytes());
    }

    private static Instant tokenTime(final byte[] response) throws Exception {
        return new TimeStampResponse(response)
                .getTimeStampToken()
                .getTimeStampInfo()
                .getGenTime()
                .toInstant();
    }
}
