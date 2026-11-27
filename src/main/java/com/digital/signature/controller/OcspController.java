package com.digital.signature.controller;

import com.digital.signature.service.OcspService;
import com.digital.signature.service.OcspService.ProfileInfo;
import com.digital.signature.service.OcspService.StatusEntry;
import com.digital.signature.service.OcspService.Times;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.support.MissingServletRequestPartException;

/** OCSP protocol and test administration endpoints. */
@RestController
@RequestMapping("/api/ocsp")
public class OcspController {
    private static final String REQUEST_TYPE = "application/ocsp-request";
    private static final String RESPONSE_TYPE = "application/ocsp-response";
    private static final Logger LOGGER = LoggerFactory.getLogger(OcspController.class);
    private static final int MAX_GET_PATH_LENGTH = 90_000;
    private final OcspService service;

    public OcspController(final OcspService service) {
        this.service = service;
    }

    /** Responds to a DER encoded OCSP request. */
    @PostMapping(value = "/responder", consumes = REQUEST_TYPE, produces = RESPONSE_TYPE)
    public ResponseEntity<byte[]> post(@RequestBody(required = false) final byte[] request) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(
                    "OCSP POST /api/ocsp/responder, {} bytes",
                    request == null ? 0 : request.length);
        }
        return response(service.respond(request));
    }

    /** Responds to the URL-encoded base64 request specified by RFC 6960. */
    @GetMapping(value = "/responder/**", produces = RESPONSE_TYPE)
    public ResponseEntity<byte[]> get(final HttpServletRequest request) {
        final String prefix = request.getContextPath() + "/api/ocsp/responder/";
        final String uri = request.getRequestURI();
        byte[] decoded = null;
        if (uri.startsWith(prefix)) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("OCSP GET {}", uri);
            }
            decoded = decodeGetRequest(uri.substring(prefix.length()));
        }
        return response(service.respond(decoded));
    }

    /** Decodes the URL-encoded base64 part of an OCSP GET URL; null when invalid. */
    public static byte[] decodeGetRequest(final String encodedPart) {
        byte[] decoded = null;
        if (encodedPart.length() > MAX_GET_PATH_LENGTH) {
            if (LOGGER.isWarnEnabled()) {
                LOGGER.warn(
                        "OCSP GET request rejected: the encoded request is {} characters (max {})",
                        encodedPart.length(),
                        MAX_GET_PATH_LENGTH);
            }
        } else {
            try {
                final String encoded =
                        URLDecoder.decode(encodedPart.replace("+", "%2B"), StandardCharsets.UTF_8);
                decoded = Base64.getDecoder().decode(encoded);
            } catch (IllegalArgumentException e) {
                if (LOGGER.isWarnEnabled()) {
                    LOGGER.warn(
                            "OCSP GET request rejected: the path is not URL-encoded base64: {}",
                            e.getMessage());
                }
            }
        }
        return decoded;
    }

    /** Lists the custom URL paths that are also served by the OCSP responder. */
    @GetMapping("/paths")
    public List<String> paths() {
        return service.customPaths();
    }

    /** Registers a custom responder URL path, e.g. {@code {"path":"/ca/ocsp"}}. */
    @PostMapping("/paths")
    public ResponseEntity<PathInfo> addPath(@RequestBody final PathInfo body) {
        final String normalized = service.addCustomPath(body == null ? null : body.path());
        return ResponseEntity.status(HttpStatus.CREATED).body(new PathInfo(normalized));
    }

    /** Removes a custom responder URL path. */
    @DeleteMapping("/paths")
    public ResponseEntity<Void> deletePath(@RequestParam("path") final String path) {
        return service.removeCustomPath(path)
                ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }

    /** A custom responder URL path. */
    public record PathInfo(String path) {}

    private static ResponseEntity<byte[]> response(final byte[] bytes) {
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(RESPONSE_TYPE))
                .cacheControl(CacheControl.noStore())
                .body(bytes);
    }

    /** Lists available issuer profiles. */
    @GetMapping("/profiles")
    public List<ProfileInfo> profiles() {
        return service.profiles();
    }

    /** Replaces an issuer profile with validated key and certificate material. */
    @PutMapping(value = "/profiles/{id}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Void> putProfile(
            @PathVariable("id") final String profileId,
            @RequestParam("file") final MultipartFile file,
            @RequestParam("issuer") final MultipartFile issuer,
            @RequestParam("keystorePassword") final String password,
            @RequestParam(value = "keyPassword", required = false) final String keyPassword,
            @RequestParam(value = "keyAlias", required = false) final String alias)
            throws IOException {
        service.putProfile(
                profileId, file.getBytes(), password, keyPassword, alias, issuer.getBytes());
        return ResponseEntity.noContent().build();
    }

    /** Deletes an issuer profile. */
    @DeleteMapping("/profiles/{id}")
    public ResponseEntity<Void> deleteProfile(@PathVariable("id") final String profileId) {
        service.deleteProfile(profileId);
        return ResponseEntity.noContent().build();
    }

    /** Lists configured statuses for a profile. */
    @GetMapping("/profiles/{id}/statuses")
    public List<StatusEntry> statuses(@PathVariable("id") final String profileId) {
        return service.statuses(profileId);
    }

    /** Sets a status for a hexadecimal serial number. */
    @PutMapping("/profiles/{id}/statuses/{serial}")
    public ResponseEntity<Void> putStatus(
            @PathVariable("id") final String profileId,
            @PathVariable final String serial,
            @RequestBody final StatusEntry status) {
        service.putStatus(profileId, serial, status);
        return ResponseEntity.noContent().build();
    }

    /** Removes a certificate status. */
    @DeleteMapping("/profiles/{id}/statuses/{serial}")
    public ResponseEntity<Void> deleteStatus(
            @PathVariable("id") final String profileId, @PathVariable final String serial) {
        service.deleteStatus(profileId, serial);
        return ResponseEntity.noContent().build();
    }

    /** Returns the fixed OCSP time configuration. */
    @GetMapping("/times")
    public Times times() {
        return service.times();
    }

    /** Sets fixed times; null fields use their defaults. */
    @PutMapping("/times")
    public ResponseEntity<Void> putTimes(@RequestBody final Times times) {
        service.setTimes(times);
        return ResponseEntity.noContent().build();
    }

    /** Clears fixed times. */
    @DeleteMapping("/times")
    public ResponseEntity<Void> clearTimes() {
        service.setTimes(new Times(null, null));
        return ResponseEntity.noContent().build();
    }

    /** Rejects invalid OCSP admin input with HTTP 400 and logs why. */
    @ExceptionHandler({
        IllegalArgumentException.class,
        MissingServletRequestParameterException.class,
        MissingServletRequestPartException.class,
        HttpMessageNotReadableException.class
    })
    public ProblemDetail badRequest(final Exception exception, final HttpServletRequest request) {
        return rejected(HttpStatus.BAD_REQUEST, exception, request);
    }

    /** Rejects a wrong Content-Type (e.g. an OCSP POST without application/ocsp-request). */
    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ProblemDetail unsupportedMediaType(
            final HttpMediaTypeNotSupportedException exception, final HttpServletRequest request) {
        return rejected(HttpStatus.UNSUPPORTED_MEDIA_TYPE, exception, request);
    }

    private static ProblemDetail rejected(
            final HttpStatus status, final Exception exception, final HttpServletRequest request) {
        if (LOGGER.isWarnEnabled()) {
            LOGGER.warn(
                    "OCSP request {} {} rejected with HTTP {}: {}",
                    request == null ? "?" : request.getMethod(),
                    request == null ? "?" : request.getRequestURI(),
                    status.value(),
                    exception.getMessage());
        }
        return ProblemDetail.forStatusAndDetail(status, exception.getMessage());
    }
}
