package com.digital.signature.controller;

import com.digital.signature.service.OcspForwarder;
import com.digital.signature.service.OcspService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Serves the OCSP responder on the custom URL paths registered in {@link OcspService}, so a
 * certificate with a fixed OCSP URL path can be simulated. POST carries the DER request in the
 * body, GET carries the URL-encoded base64 request after the path.
 */
@Component
public class OcspCustomPathFilter extends OncePerRequestFilter {
    private static final Logger LOGGER = LoggerFactory.getLogger(OcspCustomPathFilter.class);
    private static final String RESPONSE_TYPE = "application/ocsp-response";
    private final OcspService service;

    public OcspCustomPathFilter(final OcspService service) {
        super();
        this.service = service;
    }

    @Override
    protected void doFilterInternal(
            final HttpServletRequest request,
            final HttpServletResponse response,
            final FilterChain chain)
            throws ServletException, IOException {
        final String path = request.getRequestURI().substring(request.getContextPath().length());
        final String remainder = service.customPathRemainder(path);
        final boolean isGet = HttpMethod.GET.matches(request.getMethod());
        final boolean handled = remainder != null && (isGet || remainder.isEmpty());
        if (handled && LOGGER.isDebugEnabled()) {
            LOGGER.debug(
                    "OCSP {} on custom path {}, content type {}",
                    request.getMethod(),
                    path,
                    request.getContentType());
        }
        if (handled && isGet) {
            write(
                    response,
                    service.respond(
                            OcspController.decodeGetRequest(remainder), isForwarded(request)));
        } else if (handled && HttpMethod.POST.matches(request.getMethod())) {
            write(response, service.respond(readBody(request), isForwarded(request)));
        } else if (handled) {
            if (LOGGER.isWarnEnabled()) {
                LOGGER.warn(
                        "OCSP {} on custom path {} rejected with HTTP 405: only GET and POST",
                        request.getMethod(),
                        path);
            }
            response.setHeader(HttpHeaders.ALLOW, "GET, POST");
            response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        } else {
            chain.doFilter(request, response);
        }
    }

    private static boolean isForwarded(final HttpServletRequest request) {
        return request.getHeader(OcspForwarder.FORWARDED_HEADER) != null;
    }

    private static byte[] readBody(final HttpServletRequest request) throws IOException {
        final byte[] body = request.getInputStream().readNBytes(OcspService.MAX_REQUEST_SIZE + 1);
        final boolean tooLarge = body.length > OcspService.MAX_REQUEST_SIZE;
        if (tooLarge && LOGGER.isWarnEnabled()) {
            LOGGER.warn(
                    "OCSP POST body on custom path is larger than {} bytes",
                    OcspService.MAX_REQUEST_SIZE);
        }
        return tooLarge || body.length == 0 ? null : body;
    }

    private static void write(final HttpServletResponse response, final byte[] bytes)
            throws IOException {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(RESPONSE_TYPE);
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setContentLength(bytes.length);
        response.getOutputStream().write(bytes);
    }
}
