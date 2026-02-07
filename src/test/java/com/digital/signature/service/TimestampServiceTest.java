package com.digital.signature.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.security.MessageDigest;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class TimestampServiceTest {

    @Autowired private TimestampService timestampService;

    @Test
    void generateTimestampResponse_shouldReturnValidResponse_whenRequestIsValid() throws Exception {
        // Arrange
        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest("test-data".getBytes());

        TimeStampRequest request =
                reqGen.generate(NISTObjectIdentifiers.id_sha256, hash, BigInteger.valueOf(100));

        // Act
        byte[] result = timestampService.generateTimestampResponse(request.getEncoded());

        // Assert
        assertThat(result).isNotNull().isNotEmpty();

        TimeStampResponse response = new TimeStampResponse(result);
        // 0 means GRANTED
        assertThat(response.getStatus()).isEqualTo(0);
        assertThat(response.getTimeStampToken()).isNotNull();
    }

    @Test
    void generateTimestampResponse_shouldThrowException_whenRequestIsInvalidBytes() {
        // Arrange
        byte[] invalidBytes = "invalid-garbage-data".getBytes();

        // Act & Assert
        assertThatThrownBy(() -> timestampService.generateTimestampResponse(invalidBytes))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void generateTimestampResponse_shouldThrowException_whenRequestIsNull() {
        // Act & Assert
        assertThatThrownBy(() -> timestampService.generateTimestampResponse(null))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void generateTimestampResponse_shouldReturnFailureResponse_whenAlgorithmIsNotAccepted()
            throws Exception {
        // Arrange
        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        // MD5 is not in the accepted list (SHA1, SHA256, SHA512)
        MessageDigest digest = MessageDigest.getInstance("MD5");
        byte[] hash = digest.digest("test-data".getBytes());

        // Note: We need to use an OID that is NOT in the accepted list.
        TimeStampRequest request =
                reqGen.generate(PKCSObjectIdentifiers.md5, hash, BigInteger.valueOf(101));

        // Act
        byte[] result = timestampService.generateTimestampResponse(request.getEncoded());

        // Assert
        assertThat(result).isNotNull();
        TimeStampResponse response = new TimeStampResponse(result);

        // Status should NOT be 0 (GRANTED). It should be REJECTION (usually 2).
        assertThat(response.getStatus()).isNotEqualTo(0);
    }

    @Test
    void generateTimestampResponse_shouldReturnFailureResponse_whenPolicyIsNotAccepted()
            throws Exception {
        // Arrange
        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest("test-data".getBytes());

        // Requesting a policy that is different from the server's policy (1.3.6.1.4.1.13762.3)
        ASN1ObjectIdentifier unknownPolicy = new ASN1ObjectIdentifier("1.2.3.4.5.6");
        reqGen.setReqPolicy(unknownPolicy);

        TimeStampRequest request =
                reqGen.generate(NISTObjectIdentifiers.id_sha256, hash, BigInteger.valueOf(102));

        // Act
        byte[] result = timestampService.generateTimestampResponse(request.getEncoded());

        // Assert
        TimeStampResponse response = new TimeStampResponse(result);
        // Should be rejected because policy doesn't match
        assertThat(response.getStatus()).isNotEqualTo(0);
    }

    @Test
    void generateTimestampResponse_shouldIncludeNonce_whenRequestHasNonce() throws Exception {
        // Arrange
        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest("test-data".getBytes());

        BigInteger nonce = BigInteger.valueOf(123456789);
        TimeStampRequest request = reqGen.generate(NISTObjectIdentifiers.id_sha256, hash, nonce);

        // Act
        byte[] result = timestampService.generateTimestampResponse(request.getEncoded());

        // Assert
        TimeStampResponse response = new TimeStampResponse(result);
        assertThat(response.getStatus()).isEqualTo(0);
        assertThat(response.getTimeStampToken().getTimeStampInfo().getNonce()).isEqualTo(nonce);
    }

    @Test
    void generateSimpleTimestamp_shouldReturnIso8601Format() {
        // Act
        String result = timestampService.generateSimpleTimestamp();

        // Assert
        assertThat(result).isNotNull();
        // Simple regex for ISO 8601 (e.g., 2023-10-27T10:00:00.123Z)
        assertThat(result).matches("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}.*Z$");
    }

    @Test
    void generateUnixTimestamp_shouldReturnPositiveValue() {
        // Act
        long result = timestampService.generateUnixTimestamp();

        // Assert
        assertThat(result).isGreaterThan(0);
    }
}
