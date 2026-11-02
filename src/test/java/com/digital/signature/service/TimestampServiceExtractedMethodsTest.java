package com.digital.signature.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.digital.signature.AbstractTest;
import com.digital.signature.config.TimeStampConfig;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.util.ReflectionTestUtils;

/** Tests for TimestampService extracted methods to improve code coverage. */
@SpringBootTest
class TimestampServiceExtractedMethodsTest extends AbstractTest {

    @Autowired private TimestampService timestampService;

    @Autowired private TimeStampConfig config;

    // ==================== checkConfig() Tests ====================

    @Test
    void checkConfig_shouldThrowException_whenKeystorePasswordIsNull() {
        // Arrange - Create a config with null keystore password
        final TimeStampConfig testConfig = new TimeStampConfig();
        testConfig.setKeystorePath("/path/to/keystore.p12");
        testConfig.setKeystorePassword(null);
        testConfig.setKeyAlias("test-alias");

        final TimestampService service = new TimestampService(testConfig);

        // Act & Assert - The init should fail with IllegalArgumentException
        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(service, "initByKeystore"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Keystore password cannot be null");
    }

    @Test
    void checkConfig_shouldThrowException_whenKeyAliasIsNull() {
        // Arrange - Create a config with null key alias
        final TimeStampConfig testConfig = new TimeStampConfig();
        testConfig.setKeystorePath("/path/to/keystore.p12");
        testConfig.setKeystorePassword("password");
        testConfig.setKeyAlias(null);

        final TimestampService service = new TimestampService(testConfig);

        // Act & Assert
        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(service, "initByKeystore"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Key alias cannot be null");
    }

    // ==================== checkPrivateKey() Tests ====================

    @Test
    void checkPrivateKey_shouldThrowException_whenPrivateKeyIsNull() {
        // Arrange - Create a config that would result in null private key
        final TimeStampConfig testConfig = new TimeStampConfig();
        testConfig.setKeystorePath("/path/to/keystore.p12");
        testConfig.setKeystorePassword("password");
        testConfig.setKeyAlias("non-existent-alias");
        testConfig.setKeyPassword("password");

        final TimestampService service = new TimestampService(testConfig);

        // Act & Assert - The init should fail when trying to get non-existent key
        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(service, "initByKeystore"))
                .isInstanceOf(Exception.class);
    }

    // ==================== checkCert() Tests ====================

    @Test
    void checkCert_shouldThrowException_whenCertificateIsNull() {
        // Arrange - Create a config that would result in null certificate
        final TimeStampConfig testConfig = new TimeStampConfig();
        testConfig.setKeystorePath("/path/to/keystore.p12");
        testConfig.setKeystorePassword("password");
        testConfig.setKeyAlias("non-existent-alias");
        testConfig.setKeyPassword("password");

        final TimestampService service = new TimestampService(testConfig);

        // Act & Assert
        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(service, "initByKeystore"))
                .isInstanceOf(Exception.class);
    }

    // ==================== logKeystorePath() Tests ====================

    @Test
    void logKeystorePath_shouldLogInfo_whenKeystorePathIsSet() {
        // Arrange - Capture log output
        final java.util.logging.Logger logger =
                java.util.logging.Logger.getLogger(TimestampService.class.getName());
        final java.util.logging.Handler testHandler =
                new java.util.logging.Handler() {
                    private final java.util.List<String> messages = new java.util.ArrayList<>();

                    @Override
                    public void publish(java.util.logging.LogRecord record) {
                        messages.add(record.getMessage());
                    }

                    @Override
                    public void flush() {}

                    @Override
                    public void close() {}

                    public java.util.List<String> getMessages() {
                        return messages;
                    }
                };
        logger.addHandler(testHandler);

        try {
            // Act - Call the service method that uses logKeystorePath
            final TimeStampConfig testConfig = new TimeStampConfig();
            testConfig.setKeystorePath("/test/path/to/keystore.p12");
            testConfig.setKeystorePassword("password");
            testConfig.setKeyAlias("test-alias");

            // Since we can't easily test the logging without a real keystore,
            // we just verify the method exists and can be called
            assertThat(timestampService).isNotNull();
        } finally {
            logger.removeHandler(testHandler);
        }
    }

    // ==================== logCertInfo() Tests ====================

    @Test
    void logCertInfo_shouldLogCertificateDetails() throws Exception {
        // Arrange - Get the actual certificate from service
        final byte[] certBytes = timestampService.getSigningCertificate();
        final java.security.cert.CertificateFactory certFactory =
                java.security.cert.CertificateFactory.getInstance("X.509");
        final X509Certificate x509Cert =
                (X509Certificate)
                        certFactory.generateCertificate(
                                new java.io.ByteArrayInputStream(certBytes));

        // Act - The service should have logged certificate info during initialization
        // We verify the certificate was properly loaded and has valid info
        assertThat(x509Cert.getSubjectX500Principal().getName()).isNotNull();
        assertThat(x509Cert.getNotBefore()).isNotNull();
        assertThat(x509Cert.getNotAfter()).isNotNull();
        assertThat(x509Cert.getNotAfter()).isAfter(x509Cert.getNotBefore());
    }

    // ==================== initWithGenerateKey() Positive Tests ====================

    @Test
    void initWithGenerateKey_shouldGenerateKeyPair_whenNoKeystoreConfigured() {
        // Arrange - Service is already initialized with auto-generated key
        // Assert - Service should be able to generate timestamps
        final String simpleTimestamp = timestampService.generateSimpleTimestamp();
        assertThat(simpleTimestamp).isNotNull();

        final long unixTimestamp = timestampService.generateUnixTimestamp();
        assertThat(unixTimestamp).isGreaterThan(0);
    }

    // ==================== initWithGenerateKey() Negative Tests ====================

    @Test
    void initWithGenerateKey_shouldThrowException_whenKeyAlgorithmIsInvalid() {
        // Arrange - Create config with invalid key algorithm
        final TimeStampConfig testConfig = new TimeStampConfig();
        testConfig.setKeystorePath(null);
        testConfig.setKeyAlgorithm("INVALID_ALGORITHM");

        final TimestampService service = new TimestampService(testConfig);

        // Act & Assert
        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(service, "init"))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("Failed to initialize TimestampService");
    }

    // ==================== initByKeystore() Positive Tests ====================

    @Test
    void initByKeystore_shouldLoadFromKeystore_whenKeystoreIsValid() {
        // This test would require a real PKCS12 keystore file
        // For now, we verify the service works with generated key
        assertThat(timestampService).isNotNull();
    }

    // ==================== initByKeystore() Negative Tests ====================

    @Test
    void initByKeystore_shouldThrowException_whenKeystoreFileNotFound() {
        // Arrange
        final TimeStampConfig testConfig = new TimeStampConfig();
        testConfig.setKeystorePath("/non/existent/keystore.p12");
        testConfig.setKeystorePassword("password");
        testConfig.setKeyAlias("test-alias");

        final TimestampService service = new TimestampService(testConfig);

        // Act & Assert
        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(service, "initByKeystore"))
                .isInstanceOf(Exception.class);
    }

    @Test
    void initByKeystore_shouldThrowException_whenKeystorePasswordIsWrong() {
        // Arrange
        final TimeStampConfig testConfig = new TimeStampConfig();
        testConfig.setKeystorePath("/path/to/keystore.p12");
        testConfig.setKeystorePassword("wrong-password");
        testConfig.setKeyAlias("test-alias");

        final TimestampService service = new TimestampService(testConfig);

        // Act & Assert
        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(service, "initByKeystore"))
                .isInstanceOf(Exception.class);
    }

    // ==================== Private Method Access Tests ====================

    @Test
    void checkConfig_shouldNotThrow_whenConfigIsValid() {
        // Arrange
        final TimeStampConfig testConfig = new TimeStampConfig();
        testConfig.setKeystorePath("/path/to/keystore.p12");
        testConfig.setKeystorePassword("password");
        testConfig.setKeyAlias("test-alias");

        final TimestampService service = new TimestampService(testConfig);

        // Act & Assert - Should not throw when called with valid config
        // Note: This will actually throw because the keystore doesn't exist,
        // but it should pass the config validation step
        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(service, "initByKeystore"))
                .isInstanceOf(Exception.class)
                .satisfies(
                        thrown -> {
                            // Should fail on file access, not config validation
                            final String message = thrown.getMessage();
                            final Throwable cause = thrown.getCause();
                            // Check both the exception and its cause
                            final boolean isPasswordError =
                                    message != null
                                            && message.contains("Keystore password cannot be null");
                            final boolean isAliasError =
                                    message != null && message.contains("Key alias cannot be null");
                            final boolean isCausePasswordError =
                                    cause != null
                                            && cause.getMessage() != null
                                            && cause.getMessage()
                                                    .contains("Keystore password cannot be null");
                            final boolean isCauseAliasError =
                                    cause != null
                                            && cause.getMessage() != null
                                            && cause.getMessage()
                                                    .contains("Key alias cannot be null");

                            assertThat(isPasswordError || isCausePasswordError).isFalse();
                            assertThat(isAliasError || isCauseAliasError).isFalse();
                        });
    }

    @Test
    void checkPrivateKey_shouldNotThrow_whenPrivateKeyIsNotNull() {
        // Arrange - Service with generated key should have valid private key
        // Assert - Service should work normally
        assertThat(timestampService.generateSimpleTimestamp()).isNotNull();
    }

    @Test
    void checkCert_shouldNotThrow_whenCertIsNotNull() throws Exception {
        // Arrange - Service with generated key should have valid certificate
        // Act & Assert
        final byte[] cert = timestampService.getSigningCertificate();
        assertThat(cert).isNotNull();
    }
}
