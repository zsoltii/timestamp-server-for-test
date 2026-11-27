package com.digital.signature.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.digital.signature.config.TimeStampConfig;
import com.digital.signature.service.TimestampService;
import com.digital.signature.util.EkuTestKeystore;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class TimestampControllerEkuTest {
    @Test
    void controllerPassesFlagAndPropagatesFailures() throws Exception {
        TimestampService service = mock(TimestampService.class);
        TimestampController controller = new TimestampController(service);
        MockMultipartFile file = new MockMultipartFile("file", new byte[] {1});
        assertThat(
                        controller
                                .updateSigningKey(file, "password", null, null, false)
                                .getStatusCode()
                                .value())
                .isEqualTo(200);
        verify(service).updateSigningKey(new byte[] {1}, "password", null, null, false);
        doThrow(new IllegalStateException("invalid"))
                .when(service)
                .updateSigningKey(new byte[] {1}, "password", null, null, true);
        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> controller.updateSigningKey(file, "password", null, null, true))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void multipartDefaultsToStrictAndAcceptsExplicitFalse() throws Exception {
        TimestampService service = new TimestampService(new TimeStampConfig());
        service.init();
        MockMvc mvc =
                MockMvcBuilders.standaloneSetup(new TimestampController(service))
                        .setControllerAdvice(new ErrorHandlerController())
                        .build();
        MockMultipartFile file =
                new MockMultipartFile(
                        "file",
                        "test.p12",
                        "application/x-pkcs12",
                        EkuTestKeystore.create(false, KeyPurposeId.id_kp_timeStamping));
        mvc.perform(
                        multipart("/api/timestamp/update-key")
                                .file(file)
                                .param("keystorePassword", "password"))
                .andExpect(status().isInternalServerError());
        mvc.perform(
                        multipart("/api/timestamp/update-key")
                                .file(file)
                                .param("keystorePassword", "password")
                                .param("requireCriticalEku", "true"))
                .andExpect(status().isInternalServerError());
        mvc.perform(
                        multipart("/api/timestamp/update-key")
                                .file(file)
                                .param("keystorePassword", "password")
                                .param("requireCriticalEku", "false"))
                .andExpect(status().isOk());
        mvc.perform(
                        multipart("/api/timestamp/update-key")
                                .file(file)
                                .param("keystorePassword", "password")
                                .param("requireCriticalEku", "invalid"))
                .andExpect(status().isBadRequest());
    }
}
