package com.digital.signature.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.digital.signature.service.OcspService;
import com.digital.signature.service.OcspService.Times;
import java.time.Instant;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class OcspControllerTest {
    private final OcspService service = new OcspService();
    private final OcspController controller = new OcspController(service);

    @Test
    void postReturnsProtocolErrorWithCorrectMediaTypeForMalformedDer() throws Exception {
        ResponseEntity<byte[]> response = controller.post(new byte[] {1, 2});
        assertThat(response.getHeaders().getContentType().toString())
                .isEqualTo("application/ocsp-response");
        assertThat(new OCSPResp(response.getBody()).getStatus())
                .isEqualTo(OCSPRespBuilder.MALFORMED_REQUEST);
    }

    @Test
    void addPathRegistersAndListsNormalizedPath() {
        ResponseEntity<OcspController.PathInfo> created =
                controller.addPath(new OcspController.PathInfo("/ca/ocsp/"));
        assertThat(created.getStatusCode().value()).isEqualTo(201);
        assertThat(created.getBody().path()).isEqualTo("/ca/ocsp");
        assertThat(controller.paths()).containsExactly("/ca/ocsp");
    }

    @Test
    void addPathRejectsMissingOrReservedPath() {
        assertThatThrownBy(() -> controller.addPath(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> controller.addPath(new OcspController.PathInfo("/api/x")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(controller.badRequest(new IllegalArgumentException("x"), null).getStatus())
                .isEqualTo(400);
    }

    @Test
    void deletePathReturnsNoContentOrNotFound() {
        service.addCustomPath("/ocsp");
        assertThat(controller.deletePath("/ocsp").getStatusCode().value()).isEqualTo(204);
        assertThat(controller.deletePath("/ocsp").getStatusCode().value()).isEqualTo(404);
    }

    @Test
    void getDecodesPercentEncodedBase64AndHandlesBadEncoding() throws Exception {
        MockHttpServletRequest request =
                new MockHttpServletRequest("GET", "/ctx/api/ocsp/responder/%2F%2B%3D%3D");
        request.setContextPath("/ctx");
        assertThat(new OCSPResp(controller.get(request).getBody()).getStatus())
                .isEqualTo(OCSPRespBuilder.MALFORMED_REQUEST);
        request.setRequestURI("/ctx/api/ocsp/responder/not-base64!");
        assertThat(new OCSPResp(controller.get(request).getBody()).getStatus())
                .isEqualTo(OCSPRespBuilder.MALFORMED_REQUEST);
    }

    @Test
    void getPassesDecodedBase64IncludingSlashAndPlusToService() {
        OcspService mockService = mock(OcspService.class);
        OcspController target = new OcspController(mockService);
        byte[] decoded = new byte[] {(byte) 0xff, (byte) 0xee};
        when(mockService.respond(decoded)).thenReturn(new byte[] {1});
        MockHttpServletRequest request =
                new MockHttpServletRequest("GET", "/api/ocsp/responder/%2F%2B4%3D");
        assertThat(target.get(request).getBody()).containsExactly(1);
        verify(mockService).respond(decoded);
    }

    @Test
    void managesIndependentTimesAndRejectsInvalidOrdering() {
        Instant start = Instant.parse("2027-01-01T00:00:00Z");
        controller.putTimes(new Times(start, start.plusSeconds(5)));
        assertThat(controller.times()).isEqualTo(new Times(start, start.plusSeconds(5)));
        assertThatThrownBy(() -> controller.putTimes(new Times(start, start.minusSeconds(1))))
                .isInstanceOf(IllegalArgumentException.class);
        controller.clearTimes();
        assertThat(controller.times()).isEqualTo(new Times(null, null));
    }

    @Test
    void postEmptyBodyReturnsProtocolMalformedRequestOverHttp() throws Exception {
        MockMvc mvc =
                MockMvcBuilders.standaloneSetup(controller)
                        .setControllerAdvice(new ErrorHandlerController())
                        .build();
        byte[] body =
                mvc.perform(post("/api/ocsp/responder").contentType("application/ocsp-request"))
                        .andExpect(status().isOk())
                        .andExpect(content().contentType("application/ocsp-response"))
                        .andReturn()
                        .getResponse()
                        .getContentAsByteArray();
        assertThat(new OCSPResp(body).getStatus()).isEqualTo(OCSPRespBuilder.MALFORMED_REQUEST);
    }
}
