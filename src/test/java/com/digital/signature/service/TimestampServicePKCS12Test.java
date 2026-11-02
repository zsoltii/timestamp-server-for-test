package com.digital.signature.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.digital.signature.AbstractTest;
import com.digital.signature.config.TimeStampConfig;
import com.digital.signature.util.TestKeystoreGenerator;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Test suite for PKCS12 keystore loading functionality in TimestampService. Tests both positive
 * scenarios (successful loading) and negative scenarios (error cases).
 */
class TimestampServicePKCS12Test extends AbstractTest {

    @TempDir Path tempDir;

    private TimestampService timestampService;
    private TimeStampConfig config;
    private Path keystorePath;

    @BeforeEach
    void setUp() {
        config = new TimeStampConfig();
        // Set default configuration
        config.setKeyAlgorithm("RSA");
        config.setKeySize(2048);
        config.setSignatureAlgorithm("SHA256WithRSA");
        config.setCertificateSubject("CN=Test Timestamp Authority, O=Test, C=HU");
        config.setPolicyId("1.3.6.1.4.1.13762.3");
        config.setValidityDays(365);

        timestampService = new TimestampService(config);
        keystorePath = tempDir.resolve("test-keystore.p12");
    }

    /** Helper method to generate RSA keystore for each test */
    private void generateRSAKeystore(String keystorePassword, String keyAlias, String keyPassword)
            throws Exception {
        TestKeystoreGenerator.generateTestKeystore(
                keystorePath.toString(), keystorePassword, keyAlias, keyPassword);
    }

    /** Helper method to generate EC keystore for each test */
    private void generateECKeystore(String keystorePassword, String keyAlias, String keyPassword)
            throws Exception {
        TestKeystoreGenerator.generateTestKeystoreWithEC(
                keystorePath.toString(), keystorePassword, keyAlias, keyPassword);
    }

    // ========== POSITIVE TESTS ==========

    @Test
    void init_shouldLoadKeystoreSuccessfully_whenValidPKCS12WithRSAProvided() throws Exception {
        // Arrange - Generate RSA keystore
        generateRSAKeystore("testPassword", "testKey", "keyPassword");

        config.setKeystorePath(keystorePath.toString());
        config.setKeystorePassword("testPassword");
        config.setKeyAlias("testKey");
        config.setKeyPassword("keyPassword");

        // Act
        timestampService.init();

        // Assert - If initialization succeeds without exception, the test passes
        // We can verify by generating a timestamp
        String timestamp = timestampService.generateSimpleTimestamp();
        assertThat(timestamp).isNotNull().isNotEmpty();
    }

    @Test
    void init_shouldLoadKeystoreSuccessfully_whenValidPKCS12WithECProvided() throws Exception {
        // Arrange - Generate EC keystore
        generateECKeystore("testPassword", "ecTestKey", "keyPassword");

        config.setKeystorePath(keystorePath.toString());
        config.setKeystorePassword("testPassword");
        config.setKeyAlias("ecTestKey");
        config.setKeyPassword("keyPassword");
        config.setSignatureAlgorithm("SHA256withECDSA"); // EC requires ECDSA signature

        // Act
        timestampService.init();

        // Assert - If initialization succeeds without exception, the test passes
        // We can verify by generating a timestamp
        String timestamp = timestampService.generateSimpleTimestamp();
        assertThat(timestamp).isNotNull().isNotEmpty();
    }

    @Test
    void init_shouldLoadKeystoreSuccessfully_whenKeyPasswordNotProvided() throws Exception {
        // Arrange - Generate RSA keystore with same password for keystore and key
        generateRSAKeystore("samePassword", "testKey", "samePassword");

        config.setKeystorePath(keystorePath.toString());
        config.setKeystorePassword("samePassword");
        config.setKeyAlias("testKey");
        // Not setting keyPassword - should use keystorePassword

        // Act
        timestampService.init();

        // Assert
        String timestamp = timestampService.generateSimpleTimestamp();
        assertThat(timestamp).isNotNull().isNotEmpty();
    }

    @Test
    void init_shouldGenerateKeyPair_whenNoKeystoreConfigured() {
        // Arrange - No keystore configuration
        // keystorePath is not set

        // Act
        timestampService.init();

        // Assert - Should successfully initialize with generated key pair
        String timestamp = timestampService.generateSimpleTimestamp();
        assertThat(timestamp).isNotNull().isNotEmpty();
    }

    @Test
    void generateTimestampResponse_shouldWorkWithLoadedRSAKeystore() throws Exception {
        // Arrange - Generate RSA keystore
        generateRSAKeystore("testPassword", "testKey", "keyPassword");

        config.setKeystorePath(keystorePath.toString());
        config.setKeystorePassword("testPassword");
        config.setKeyAlias("testKey");
        config.setKeyPassword("keyPassword");

        timestampService.init();

        // Create a simple timestamp request (SHA-256 hash of "test data")
        byte[] testData = "test data".getBytes();
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(testData);

        org.bouncycastle.tsp.TimeStampRequestGenerator reqGen =
                new org.bouncycastle.tsp.TimeStampRequestGenerator();
        reqGen.setCertReq(true);
        org.bouncycastle.tsp.TimeStampRequest request =
                reqGen.generate(
                        org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256,
                        hash,
                        java.math.BigInteger.valueOf(100));

        // Act
        byte[] response = timestampService.generateTimestampResponse(request.getEncoded());

        // Assert
        assertThat(response).isNotNull().isNotEmpty();
        org.bouncycastle.tsp.TimeStampResponse tsResponse =
                new org.bouncycastle.tsp.TimeStampResponse(response);
        assertThat(tsResponse.getStatus()).isEqualTo(0); // PKIStatus.GRANTED
    }

    // ========== NEGATIVE TESTS ==========

    @Test
    void init_shouldThrowException_whenKeystoreFileNotFound() {
        // Arrange
        config.setKeystorePath("/nonexistent/path/keystore.p12");
        config.setKeystorePassword("testPassword");
        config.setKeyAlias("testKey");
        config.setKeyPassword("keyPassword");

        // Act & Assert
        assertThatThrownBy(() -> timestampService.init())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Failed to initialize TimestampService");
    }

    @Test
    void init_shouldThrowException_whenKeyAliasIsNull() throws Exception {
        // Arrange - Generate RSA keystore
        generateRSAKeystore("testPassword", "testKey", "keyPassword");

        config.setKeystorePath(keystorePath.toString());
        config.setKeystorePassword("testPassword");
        config.setKeyAlias(null);
        config.setKeyPassword("keyPassword");

        // Act & Assert
        assertThatThrownBy(() -> timestampService.init())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Failed to initialize TimestampService")
                .cause()
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Key alias cannot be null");
    }
}
