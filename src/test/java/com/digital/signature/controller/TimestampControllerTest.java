package com.digital.signature.controller;

import static org.assertj.core.api.Assertions.assertThat;
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
}
