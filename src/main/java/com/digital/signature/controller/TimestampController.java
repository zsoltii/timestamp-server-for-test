package com.digital.signature.controller;

import com.digital.signature.service.TimestampService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/timestamp")
public class TimestampController {

    private final TimestampService timestampService;

    @Autowired
    public TimestampController(TimestampService timestampService) {
        this.timestampService = timestampService;
    }

    /**
     * Handle RFC 3161 Timestamp Query Content-Type: application/timestamp-query Returns:
     * application/timestamp-reply
     */
    @PostMapping(consumes = "application/timestamp-query", produces = "application/timestamp-reply")
    public ResponseEntity<byte[]> handleTimestampQuery(@RequestBody byte[] requestBytes)
            throws Exception {
        byte[] responseBytes = timestampService.generateTimestampResponse(requestBytes);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType("application/timestamp-reply"));

        return ResponseEntity.ok().headers(headers).body(responseBytes);
    }

    /** Get current timestamp in simple format (ISO 8601) */
    @GetMapping("/simple")
    public ResponseEntity<String> getSimpleTimestamp() {
        String timestamp = timestampService.generateSimpleTimestamp();
        return ResponseEntity.ok(timestamp);
    }

    /** Get current timestamp in Unix format (seconds since epoch) */
    @GetMapping("/unix")
    public ResponseEntity<Long> getUnixTimestamp() {
        long timestamp = timestampService.generateUnixTimestamp();
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
     * @return Success message
     * @throws IllegalArgumentException if the update fails due to invalid input
     * @throws IllegalStateException if the update fails due to internal error
     */
    @PostMapping("/update-key")
    public ResponseEntity<String> updateSigningKey(
            @RequestParam("file") org.springframework.web.multipart.MultipartFile pkcs12File,
            @RequestParam("keystorePassword") String keystorePassword,
            @RequestParam(value = "keyPassword", required = false) String keyPassword,
            @RequestParam(value = "keyAlias", required = false) String keyAlias)
            throws Exception {
        timestampService.updateSigningKey(
                pkcs12File.getBytes(), keystorePassword, keyPassword, keyAlias);
        return ResponseEntity.ok("Signing key updated successfully");
    }
}
