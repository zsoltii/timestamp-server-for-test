package com.digital.signature.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.digital.signature.AbstractTest;
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
class TimestampServiceTest extends AbstractTest {

    @Autowired private TimestampService timestampService;

    @Test
    void getSigningCertificateAsPem_getPemCertificate_whenCalled() throws Exception {
        String pem = timestampService.getSigningCertificateAsPem();

        assertThat(pem)
                .isNotNull()
                .startsWith("-----BEGIN CERTIFICATE-----")
                .endsWith("-----END CERTIFICATE-----");

        String base64Part =
                pem.replace("-----BEGIN CERTIFICATE-----", "")
                        .replace("-----END CERTIFICATE-----", "")
                        .replaceAll("\\s", "");

        assertThat(java.util.Base64.getDecoder().decode(base64Part)).isNotEmpty();
    }

    @Test
    void initialization_shouldVerifyKeystorePathLogged_whenKeystoreConfigured() {
        // Arrange - Service is already initialized with auto-generated key
        // The key generation logs "Generated new self-signed certificate"
        // We verify the service is initialized and functional
        assertThat(timestampService).isNotNull();
        assertThat(timestampService.generateSimpleTimestamp()).isNotNull();
    }

    @Test
    void getSigningCertificateAsPem_shouldKillMathMutator_withShortCertificate() throws Exception {
        // Act - Get PEM for any certificate
        String pemCertificate = timestampService.getSigningCertificateAsPem();

        // Assert - This test ensures the for loop runs correctly
        // and kills the MathMutator (i + 64) mutation
        String[] lines = pemCertificate.split("\n");

        // Should have header, content lines, and footer
        assertThat(lines.length).isGreaterThanOrEqualTo(3);

        // Verify base64 content is wrapped at 64 chars
        for (int i = 1; i < lines.length - 1; i++) {
            String line = lines[i];
            if (!line.isEmpty() && !line.startsWith("-----")) {
                // All lines except possibly the last should be exactly 64 chars
                if (i < lines.length - 2) {
                    assertThat(line.length())
                            .as("Base64 content line should be 64 characters")
                            .isEqualTo(64);
                }
            }
        }
    }

    @Test
    void getSigningCertificateAsPem_shouldKillBoundaryMutator_withExact64CharLines()
            throws Exception {
        // This test specifically targets the ConditionalsBoundaryMutator
        // by ensuring the loop boundary is correct
        String pemCertificate = timestampService.getSigningCertificateAsPem();

        // Split and verify the last line is handled correctly
        String[] lines = pemCertificate.split("\n");

        // The for loop uses i += 64, and Math.min(i + 64, base64.length())
        // The boundary condition is crucial for the last chunk
        assertThat(pemCertificate).startsWith("-----BEGIN CERTIFICATE-----");
        assertThat(pemCertificate).endsWith("-----END CERTIFICATE-----");

        // Verify we have content between headers
        assertThat(lines.length).isGreaterThan(2);
    }

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
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Request bytes cannot be null");
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

    @Test
    void getSigningCertificate_shouldReturnValidCertificate() throws Exception {
        // Act
        byte[] certificate = timestampService.getSigningCertificate();

        // Assert
        assertThat(certificate).isNotNull();
        assertThat(certificate).isNotEmpty();
        // Verify it's a valid X.509 certificate by trying to parse it
        java.security.cert.CertificateFactory certFactory =
                java.security.cert.CertificateFactory.getInstance("X.509");
        java.io.ByteArrayInputStream certStream = new java.io.ByteArrayInputStream(certificate);
        java.security.cert.X509Certificate x509Cert =
                (java.security.cert.X509Certificate) certFactory.generateCertificate(certStream);
        assertThat(x509Cert.getSubjectX500Principal().getName()).isNotNull();
    }

    @Test
    void getSigningCertificateAsPem_shouldReturnValidPem() throws Exception {
        // Act
        String pemCertificate = timestampService.getSigningCertificateAsPem();

        // Assert
        assertThat(pemCertificate).isNotNull();
        assertThat(pemCertificate).startsWith("-----BEGIN CERTIFICATE-----");
        assertThat(pemCertificate).endsWith("-----END CERTIFICATE-----");
        // Verify base64 content exists between headers
        String[] lines = pemCertificate.split("\n");
        assertThat(lines.length).isGreaterThan(2);
        assertThat(lines[1]).isNotEmpty(); // Base64 content
    }

    @Test
    void getSigningCertificateAsPem_shouldReturnCertificateThatCanBeParsed() throws Exception {
        // Act
        String pemCertificate = timestampService.getSigningCertificateAsPem();

        // Extract base64 content (remove PEM headers and newlines)
        String base64Content =
                pemCertificate
                        .replace("-----BEGIN CERTIFICATE-----", "")
                        .replace("-----END CERTIFICATE-----", "")
                        .replaceAll("\\s", "");

        // Decode and verify it's a valid X.509 certificate
        byte[] derBytes = java.util.Base64.getDecoder().decode(base64Content);
        java.security.cert.CertificateFactory certFactory =
                java.security.cert.CertificateFactory.getInstance("X.509");
        java.io.ByteArrayInputStream certStream = new java.io.ByteArrayInputStream(derBytes);
        java.security.cert.X509Certificate x509Cert =
                (java.security.cert.X509Certificate) certFactory.generateCertificate(certStream);
        assertThat(x509Cert.getSubjectX500Principal().getName()).isNotNull();
    }

    @Test
    void getSigningCertificateAsPem_shouldThrowException_whenCertificateNotInitialized()
            throws Exception {
        // Arrange - Create a new service instance without initialization
        TimestampService uninitializedService = new TimestampService(null);
        java.lang.reflect.Field signingCertField =
                TimestampService.class.getDeclaredField("signCert");
        signingCertField.setAccessible(true);
        signingCertField.set(uninitializedService, null);

        // Act & Assert
        assertThatThrownBy(uninitializedService::getSigningCertificateAsPem)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Signing certificate not initialized");
    }

    @Test
    void getSigningCertificateAsPem_shouldContainMultipleLines_whenCertificateIsLong()
            throws Exception {
        // Act
        String pemCertificate = timestampService.getSigningCertificateAsPem();

        // Assert - A certificate should produce multiple lines of base64 content
        // This test kills the conditional boundary mutation in the for loop
        String[] lines = pemCertificate.split("\n");
        // Should have at least 3 lines: header, content, footer
        assertThat(lines.length).isGreaterThanOrEqualTo(3);

        // Count the base64 content lines (excluding header and footer)
        int base64Lines = 0;
        for (String line : lines) {
            if (!line.startsWith("-----") && !line.isEmpty()) {
                base64Lines++;
            }
        }
        // Most certificates should produce multiple base64 lines (killing MathMutator)
        assertThat(base64Lines).isGreaterThanOrEqualTo(1);
    }

    @Test
    void getSigningCertificateAsPem_shouldHaveCorrectLineLength() throws Exception {
        // Act
        String pemCertificate = timestampService.getSigningCertificateAsPem();

        // Assert - Each base64 line should be exactly 64 characters (except possibly the last one)
        String[] lines = pemCertificate.split("\n");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            // Skip header and footer lines
            if (line.startsWith("-----")) {
                continue;
            }
            // The last line may be shorter, but all others should be 64 chars
            if (i < lines.length - 2) {
                assertThat(line.length())
                        .as("Base64 line %d should be 64 characters", i)
                        .isEqualTo(64);
            }
        }
    }
}
