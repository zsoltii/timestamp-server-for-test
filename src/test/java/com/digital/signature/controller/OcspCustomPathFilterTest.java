package com.digital.signature.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.digital.signature.service.OcspService;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class OcspCustomPathFilterTest {
    private final OcspService service = mock(OcspService.class);
    private final OcspCustomPathFilter filter = new OcspCustomPathFilter(service);
    private final FilterChain chain = mock(FilterChain.class);

    @Test
    void postOnCustomPathIsAnsweredByTheResponder() throws Exception {
        final byte[] body = {1, 2, 3};
        when(service.customPathRemainder("/ca/ocsp")).thenReturn("");
        when(service.respond(body, false)).thenReturn(new byte[] {9});
        final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/ca/ocsp");
        request.setContent(body);
        final MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentType()).isEqualTo("application/ocsp-response");
        assertThat(response.getContentAsByteArray()).containsExactly(9);
        verifyNoInteractions(chain);
    }

    @Test
    void forwardedHeaderOnCustomPathIsPassedToTheService() throws Exception {
        final byte[] body = {4};
        when(service.customPathRemainder("/ocsp")).thenReturn("");
        when(service.respond(body, true)).thenReturn(new byte[] {8});
        final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/ocsp");
        request.setContent(body);
        request.addHeader(com.digital.signature.service.OcspForwarder.FORWARDED_HEADER, "1");
        final MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertThat(response.getContentAsByteArray()).containsExactly(8);
    }

    @Test
    void emptyPostBodyIsPassedAsNull() throws Exception {
        when(service.customPathRemainder("/ocsp")).thenReturn("");
        when(service.respond(null, false)).thenReturn(new byte[] {7});
        final MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(new MockHttpServletRequest("POST", "/ocsp"), response, chain);

        assertThat(response.getContentAsByteArray()).containsExactly(7);
    }

    @Test
    void getOnCustomPathDecodesTheBase64Remainder() throws Exception {
        when(service.customPathRemainder("/ocsp/AQID")).thenReturn("AQID");
        when(service.respond(new byte[] {1, 2, 3}, false)).thenReturn(new byte[] {5});
        final MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(new MockHttpServletRequest("GET", "/ocsp/AQID"), response, chain);

        assertThat(response.getContentAsByteArray()).containsExactly(5);
    }

    @Test
    void invalidGetRemainderProducesNullRequest() throws Exception {
        when(service.customPathRemainder("/ocsp/%%%")).thenReturn("%%%");
        when(service.respond(null, false)).thenReturn(new byte[] {6});
        final MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(new MockHttpServletRequest("GET", "/ocsp/%%%"), response, chain);

        assertThat(response.getContentAsByteArray()).containsExactly(6);
    }

    @Test
    void otherMethodsOnCustomPathAreRejected() throws Exception {
        when(service.customPathRemainder("/ocsp")).thenReturn("");
        final MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(new MockHttpServletRequest("DELETE", "/ocsp"), response, chain);

        assertThat(response.getStatus()).isEqualTo(405);
        assertThat(response.getHeader("Allow")).isEqualTo("GET, POST");
    }

    @Test
    void postOnSubPathOfCustomPathContinuesTheFilterChain() throws Exception {
        when(service.customPathRemainder("/ca/ocsp/extra")).thenReturn("extra");
        final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/ca/ocsp/extra");
        final MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        assertThat(response.getContentAsByteArray()).isEmpty();
    }

    @Test
    void otherMethodOnSubPathOfCustomPathContinuesTheFilterChain() throws Exception {
        when(service.customPathRemainder("/ca/ocsp/extra")).thenReturn("extra");
        final MockHttpServletRequest request =
                new MockHttpServletRequest("DELETE", "/ca/ocsp/extra");
        final MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void otherPathsContinueTheFilterChain() throws Exception {
        final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/unrelated");
        final MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        assertThat(response.getContentAsByteArray()).isEmpty();
    }
}
