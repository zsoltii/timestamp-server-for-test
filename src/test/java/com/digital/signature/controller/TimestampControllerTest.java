package com.digital.signature.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.digital.signature.service.TimestampService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;

class TimestampControllerTest {

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
}
