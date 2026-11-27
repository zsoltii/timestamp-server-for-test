package com.digital.signature.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.digital.signature.service.SigningCertificateInfo;
import com.digital.signature.service.TimestampService;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

class SigningCertificateInfoControllerTest {

    private final TimestampService service = mock(TimestampService.class);
    private final TimestampController controller = new TimestampController(service);

    @Test
    void returnsPublicInformationWithoutCaching() {
        final SigningCertificateInfo info =
                new SigningCertificateInfo(
                        "CN=Signer",
                        "CN=Issuer",
                        "FF",
                        Instant.parse("2020-01-01T00:00:00Z"),
                        Instant.parse("2030-01-01T00:00:00Z"),
                        "ABCD",
                        "RSA",
                        2048,
                        null);
        when(service.getSigningCertificateInfo()).thenReturn(info);

        final ResponseEntity<SigningCertificateInfo> response =
                controller.getSigningCertificateInfo();

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isEqualTo(info);
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
    }

    @Test
    void propagatesCertificateInspectionFailure() {
        when(service.getSigningCertificateInfo())
                .thenThrow(new IllegalStateException("Signing certificate not initialized"));

        assertThatThrownBy(controller::getSigningCertificateInfo)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Signing certificate not initialized");
    }
}
