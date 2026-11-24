package com.digital.signature.controller;

import com.digital.signature.service.SigningCertificateInfo;
import com.digital.signature.service.TimestampService;
import java.time.Instant;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/timestamp")
public class TimestampController {

    private static final String TIMESTAMP_QUERY = "application/timestamp-query";
    private static final String TIMESTAMP_REPLY = "application/timestamp-reply";

    private final TimestampService timestampService;

    @Autowired
    public TimestampController(final TimestampService timestampService) {
        this.timestampService = timestampService;
    }

    /**
     * Handle RFC 3161 Timestamp Query Content-Type: application/timestamp-query Returns:
     * application/timestamp-reply
     */
    @PostMapping(consumes = TIMESTAMP_QUERY, produces = TIMESTAMP_REPLY)
    public ResponseEntity<byte[]> handleTimestampQuery(@RequestBody final byte[] requestBytes)
            throws java.io.IOException, org.bouncycastle.tsp.TSPException {
        final byte[] responseBytes = timestampService.generateTimestampResponse(requestBytes);

        final HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType(TIMESTAMP_REPLY));

        return ResponseEntity.ok().headers(headers).body(responseBytes);
    }

    /**
     * Handle RFC 3161 Timestamp Query with a caller supplied time, which may be in the past or in
     * the future. Content-Type: application/timestamp-query Returns: application/timestamp-reply
     *
     * @param requestBytes the DER encoded timestamp request
     * @param time the time to stamp in {@code yyyy-MM-dd HH:mm:ssZ} format (UTC when no zone is
     *     given), the current time when empty
     * @return the timestamp response, the used time is also returned in the {@code
     *     X-Timestamp-Time} header
     * @throws ResponseStatusException with status 400 if the time is not valid
     */
    @PostMapping(value = "/custom", consumes = TIMESTAMP_QUERY, produces = TIMESTAMP_REPLY)
    public ResponseEntity<byte[]> handleCustomTimeTimestampQuery(
            @RequestBody final byte[] requestBytes,
            @RequestParam(value = "time", required = false) final String time) {
        final Instant genTime;
        try {
            genTime = timestampService.parseTimestampTime(time);
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
        final byte[] responseBytes =
                timestampService.generateTimestampResponse(requestBytes, genTime);

        final HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType(TIMESTAMP_REPLY));
        headers.set("X-Timestamp-Time", genTime.toString());

        return ResponseEntity.ok().headers(headers).body(responseBytes);
    }

    /**
     * Get the fixed time written into every timestamp
     *
     * @return the fixed time in ISO 8601 (UTC), or 204 No Content when the current time is used
     */
    @GetMapping("/fixed-time")
    public ResponseEntity<String> getFixedTime() {
        return fixedTimeResponse(timestampService.getFixedTime());
    }

    /**
     * Set the fixed time written into every timestamp made by {@code POST /api/timestamp}. The
     * setting is kept in memory only.
     *
     * @param time the time in {@code yyyy-MM-dd HH:mm:ssZ} format (UTC when no zone is given, the
     *     zone can be an offset, an abbreviation like CEST or a region id like Europe/Budapest),
     *     empty clears the fixed time so the current time is used
     * @return the fixed time in ISO 8601 (UTC), or 204 No Content when it has been cleared
     * @throws ResponseStatusException with status 400 if the time is not valid
     */
    @PutMapping("/fixed-time")
    public ResponseEntity<String> updateFixedTime(
            @RequestParam(value = "time", required = false) final String time) {
        try {
            return fixedTimeResponse(timestampService.updateFixedTime(time));
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
    }

    /** Clear the fixed time, the current time is used again */
    @DeleteMapping("/fixed-time")
    public ResponseEntity<String> clearFixedTime() {
        return fixedTimeResponse(timestampService.updateFixedTime(null));
    }

    private static ResponseEntity<String> fixedTimeResponse(final Instant fixedTime) {
        return fixedTime == null
                ? ResponseEntity.noContent().build()
                : ResponseEntity.ok(fixedTime.toString());
    }

    /** Get current timestamp in simple format (ISO 8601) */
    @GetMapping("/simple")
    public ResponseEntity<String> getSimpleTimestamp() {
        final String timestamp = timestampService.generateSimpleTimestamp();
        return ResponseEntity.ok(timestamp);
    }

    /** Get current timestamp in Unix format (seconds since epoch) */
    @GetMapping("/unix")
    public ResponseEntity<Long> getUnixTimestamp() {
        final long timestamp = timestampService.generateUnixTimestamp();
        return ResponseEntity.ok(timestamp);
    }

    /** Health check endpoint */
    @GetMapping("/health")
    public String healthCheck() {
        return "Timestamp Server is running";
    }

    /**
     * Update the signing key with a new PKCS12 file
     *
     * @param pkcs12File The PKCS12 file containing the new signing key and certificate
     * @param keystorePassword The password for the PKCS12 keystore
     * @param keyPassword The password for the private key (optional, defaults to keystorePassword)
     * @param keyAlias The alias of the key in the keystore (optional, defaults to first key found)
     * @param requireCriticalEku Whether the timestamping EKU must be critical (defaults to true)
     * @return Success message
     * @throws IllegalArgumentException if the update fails due to invalid input
     * @throws IllegalStateException if the update fails due to internal error
     */
    @PostMapping("/update-key")
    public ResponseEntity<String> updateSigningKey(
            @RequestParam("file") final MultipartFile pkcs12File,
            @RequestParam("keystorePassword") final String keystorePassword,
            @RequestParam(value = "keyPassword", required = false) final String keyPassword,
            @RequestParam(value = "keyAlias", required = false) final String keyAlias,
            @RequestParam(value = "requireCriticalEku", defaultValue = "true")
                    final boolean requireCriticalEku)
            throws Exception {
        timestampService.updateSigningKey(
                pkcs12File.getBytes(), keystorePassword, keyPassword, keyAlias, requireCriticalEku);
        return ResponseEntity.ok("Signing key updated successfully");
    }

    /**
     * Get the signing certificate in DER format
     *
     * @return The certificate as a byte array in DER format
     * @throws Exception if the certificate cannot be retrieved
     */
    @GetMapping("/certificate")
    public ResponseEntity<byte[]> getSigningCertificate() throws Exception {
        final byte[] certificate = timestampService.getSigningCertificate();

        final HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType("application/pkix-cert"));
        headers.set("Content-Disposition", "attachment; filename=signing-certificate.cer");

        return ResponseEntity.ok().headers(headers).body(certificate);
    }

    /**
     * Returns public information about the current signing certificate.
     *
     * @return certificate and public key details, without private key material
     * @throws IllegalStateException if the certificate cannot be inspected
     */
    @GetMapping("/certificate/info")
    public ResponseEntity<SigningCertificateInfo> getSigningCertificateInfo() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(timestampService.getSigningCertificateInfo());
    }

    /**
     * Get the signing certificate in PEM format
     *
     * @return The certificate as a String in PEM format
     * @throws Exception if the certificate cannot be retrieved
     */
    @GetMapping(value = "/certificate/pem", produces = "application/x-pem-file")
    public ResponseEntity<String> getSigningCertificateAsPem() throws Exception {
        final String pemCertificate = timestampService.getSigningCertificateAsPem();

        final HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType("application/x-pem-file"));
        headers.set("Content-Disposition", "attachment; filename=signing-certificate.pem");

        return ResponseEntity.ok().headers(headers).body(pemCertificate);
    }
}
