package com.digital.signature.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.digital.signature.AbstractTest;
import com.digital.signature.service.TimestampService;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

class TimestampControllerTest extends AbstractTest {

    @Mock private TimestampService timestampService;

    @InjectMocks private TimestampController timestampController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void handleTimestampQuery_shouldReturnTimestampResponse() throws Exception {
        // Arrange
        byte[] requestBytes = "mock-request".getBytes();
        byte[] responseBytes = "mock-response".getBytes();
        when(timestampService.generateTimestampResponse(any(byte[].class)))
                .thenReturn(responseBytes);

        // Act
        ResponseEntity<byte[]> response = timestampController.handleTimestampQuery(requestBytes);

        // Assert
        assertThat(response).isNotNull();
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isEqualTo(responseBytes);
        assertThat(response.getHeaders().getContentType()).isNotNull();
        assertThat(response.getHeaders().getContentType().toString())
                .isEqualTo("application/timestamp-reply");
        verify(timestampService, times(1)).generateTimestampResponse(any(byte[].class));
    }

    @Test
    void getSimpleTimestamp_shouldReturnIso8601Timestamp() {
        // Arrange
        when(timestampService.generateSimpleTimestamp()).thenReturn("2024-01-01T00:00:00Z");

        // Act
        ResponseEntity<String> response = timestampController.getSimpleTimestamp();

        // Assert
        assertThat(response).isNotNull();
        assertThat(response.getBody()).contains("2024-01-01T00:00:00Z");
    }

    @Test
    void getUnixTimestamp_shouldReturnEpochSeconds() {
        // Arrange
        when(timestampService.generateUnixTimestamp()).thenReturn(1700000000L);

        // Act
        ResponseEntity<Long> response = timestampController.getUnixTimestamp();

        // Assert
        assertThat(response).isNotNull();
        assertThat(response.getBody()).isEqualTo(1700000000L);
    }

    @Test
    void healthCheck_shouldReturnHealthyMessage() {
        // Act
        String result = timestampController.healthCheck();

        // Assert
        assertThat(result).isEqualTo("Timestamp Server is running");
    }

    @Test
    void getSigningCertificate_shouldReturnCertificateInDerFormat() throws Exception {
        // Arrange
        byte[] mockCertificate = "mock-certificate-data".getBytes();
        when(timestampService.getSigningCertificate()).thenReturn(mockCertificate);

        // Act
        ResponseEntity<byte[]> response = timestampController.getSigningCertificate();

        // Assert
        assertThat(response).isNotNull();
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isEqualTo(mockCertificate);
        assertThat(response.getHeaders().getContentType()).isNotNull();
        assertThat(response.getHeaders().getContentType().toString())
                .isEqualTo("application/pkix-cert");
        assertThat(response.getHeaders().getFirst("Content-Disposition"))
                .contains("attachment; filename=");
        verify(timestampService, times(1)).getSigningCertificate();
    }

    @Test
    void getSigningCertificate_shouldReturnCertificateInPemFormat_whenPemRequested()
            throws Exception {
        // Arrange
        String mockPemCertificate =
                "-----BEGIN CERTIFICATE-----\nmock-base64-content\n-----END CERTIFICATE-----";
        when(timestampService.getSigningCertificateAsPem()).thenReturn(mockPemCertificate);

        // Act
        ResponseEntity<String> response = timestampController.getSigningCertificateAsPem();

        // Assert
        assertThat(response).isNotNull();
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).contains("BEGIN CERTIFICATE");
        assertThat(response.getHeaders().getContentType()).isNotNull();
        assertThat(response.getHeaders().getContentType().toString())
                .isEqualTo("application/x-pem-file");
        assertThat(response.getHeaders().getFirst("Content-Disposition"))
                .contains("attachment; filename=");
        verify(timestampService, times(1)).getSigningCertificateAsPem();
    }

    @Test
    void getSigningCertificate_shouldPropagateException_whenServiceThrows() throws Exception {
        // Arrange
        when(timestampService.getSigningCertificate())
                .thenThrow(new IllegalStateException("Certificate not initialized"));

        // Act & Assert
        assertThatThrownBy(() -> timestampController.getSigningCertificate())
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Certificate not initialized");
    }

    @Test
    void handleCustomTimeTimestampQuery_shouldUseParsedTime_whenTimeIsGiven() throws Exception {
        // Arrange
        final Instant time = Instant.parse("2020-01-31T12:30:00Z");
        final byte[] requestBytes = "mock-request".getBytes();
        final byte[] responseBytes = "mock-response".getBytes();
        when(timestampService.parseTimestampTime("2020-01-31 14:30:00+0200")).thenReturn(time);
        when(timestampService.generateTimestampResponse(requestBytes, time))
                .thenReturn(responseBytes);

        // Act
        ResponseEntity<byte[]> response =
                timestampController.handleCustomTimeTimestampQuery(
                        requestBytes, "2020-01-31 14:30:00+0200");

        // Assert
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isEqualTo(responseBytes);
        assertThat(response.getHeaders().getContentType()).isNotNull();
        assertThat(response.getHeaders().getContentType().toString())
                .isEqualTo("application/timestamp-reply");
        assertThat(response.getHeaders().getFirst("X-Timestamp-Time"))
                .isEqualTo("2020-01-31T12:30:00Z");
    }

    @Test
    void handleCustomTimeTimestampQuery_shouldReturnBadRequest_whenTimeIsInvalid() {
        // Arrange
        when(timestampService.parseTimestampTime("nonsense"))
                .thenThrow(new IllegalArgumentException("Invalid time 'nonsense'"));

        // Act & Assert
        assertThatThrownBy(
                        () ->
                                timestampController.handleCustomTimeTimestampQuery(
                                        "mock-request".getBytes(), "nonsense"))
                .isInstanceOfSatisfying(
                        ResponseStatusException.class,
                        e -> assertThat(e.getStatusCode().value()).isEqualTo(400));
        verify(timestampService, never()).generateTimestampResponse(any(), any());
    }

    @Test
    void getFixedTime_shouldReturnIsoTime_whenFixedTimeIsSet() {
        when(timestampService.getFixedTime()).thenReturn(Instant.parse("2020-01-31T12:30:00Z"));

        ResponseEntity<String> response = timestampController.getFixedTime();

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isEqualTo("2020-01-31T12:30:00Z");
    }

    @Test
    void getFixedTime_shouldReturnNoContent_whenFixedTimeIsNotSet() {
        when(timestampService.getFixedTime()).thenReturn(null);

        ResponseEntity<String> response = timestampController.getFixedTime();

        assertThat(response.getStatusCode().value()).isEqualTo(204);
        assertThat(response.getBody()).isNull();
    }

    @Test
    void updateFixedTime_shouldReturnIsoTime_whenTimeIsValid() {
        when(timestampService.updateFixedTime("2020-01-31 14:30:00+0200"))
                .thenReturn(Instant.parse("2020-01-31T12:30:00Z"));

        ResponseEntity<String> response =
                timestampController.updateFixedTime("2020-01-31 14:30:00+0200");

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isEqualTo("2020-01-31T12:30:00Z");
    }

    @Test
    void updateFixedTime_shouldReturnNoContent_whenTimeIsEmpty() {
        when(timestampService.updateFixedTime("")).thenReturn(null);

        ResponseEntity<String> response = timestampController.updateFixedTime("");

        assertThat(response.getStatusCode().value()).isEqualTo(204);
    }

    @Test
    void updateFixedTime_shouldReturnBadRequest_whenTimeIsInvalid() {
        when(timestampService.updateFixedTime("nonsense"))
                .thenThrow(new IllegalArgumentException("Invalid time 'nonsense'"));

        assertThatThrownBy(() -> timestampController.updateFixedTime("nonsense"))
                .isInstanceOfSatisfying(
                        ResponseStatusException.class,
                        e -> assertThat(e.getStatusCode().value()).isEqualTo(400));
    }

    @Test
    void clearFixedTime_shouldClearAndReturnNoContent() {
        ResponseEntity<String> response = timestampController.clearFixedTime();

        assertThat(response.getStatusCode().value()).isEqualTo(204);
        verify(timestampService).updateFixedTime(null);
    }
}
