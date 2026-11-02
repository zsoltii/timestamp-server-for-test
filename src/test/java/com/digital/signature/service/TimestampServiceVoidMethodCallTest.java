package com.digital.signature.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ch.qos.logback.classic.spi.ILoggingEvent;
import com.digital.signature.AbstractTest;
import com.digital.signature.config.TimeStampConfig;
import com.digital.signature.util.TestKeystoreGenerator;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Tests specifically designed to kill VoidMethodCall mutator mutations. These tests verify that
 * void methods produce observable side effects.
 */
class TimestampServiceVoidMethodCallTest extends AbstractTest {

    @TempDir Path tempDir;

    private TimeStampConfig config;
    private Path keystorePath;

    @BeforeEach
    void setUp() {
        config = new TimeStampConfig();
        config.setKeyAlgorithm("RSA");
        config.setKeySize(2048);
        config.setSignatureAlgorithm("SHA256WithRSA");
        config.setCertificateSubject("CN=Test Timestamp Authority, O=Test, C=HU");
        config.setPolicyId("1.3.6.1.4.1.13762.3");
        config.setValidityDays(365);

        keystorePath = tempDir.resolve("test-keystore.p12");
    }

    // ==================== logKeystorePath() Tests ====================

    @Test
    void logKeystorePath_shouldBeCalled_whenLoadingFromKeystore() throws Exception {
        // Arrange - Generate a valid keystore
        TestKeystoreGenerator.generateTestKeystore(
                keystorePath.toString(), "password", "testalias", "keypass");

        config.setKeystorePath(keystorePath.toString());
        config.setKeystorePassword("password");
        config.setKeyAlias("testalias");
        config.setKeyPassword("keypass");

        clearMemoryAppender();

        // Act
        TimestampService service = new TimestampService(config);
        service.init();

        // Assert - Verify logKeystorePath was called (kills VoidMethodCallMutator)
        List<ILoggingEvent> events = getLoggedEvents();
        boolean hasKeystorePathLog =
                events.stream()
                        .anyMatch(
                                e ->
                                        e.getFormattedMessage()
                                                .contains(
                                                        "Loading key and certificate from PKCS12 keystore"));
        assertThat(hasKeystorePathLog)
                .as("logKeystorePath should have been called and logged")
                .isTrue();
    }

    // ==================== checkPrivateKey() Tests ====================

    @Test
    void checkPrivateKey_shouldBeCalled_whenLoadingFromKeystore() throws Exception {
        // Arrange - Generate keystore with key
        TestKeystoreGenerator.generateTestKeystore(
                keystorePath.toString(), "password", "testalias", "keypass");

        config.setKeystorePath(keystorePath.toString());
        config.setKeystorePassword("password");
        config.setKeyAlias("testalias");
        config.setKeyPassword("keypass");

        // Act & Assert - If checkPrivateKey is removed (VoidMethodCallMutator),
        // the service might fail later or behave unexpectedly
        TimestampService service = new TimestampService(config);
        service.init();

        // Verify service works correctly (implies checkPrivateKey was called)
        assertThat(service.generateSimpleTimestamp()).isNotNull();
    }

    @Test
    void checkPrivateKey_shouldDetectNull_whenKeyNotFound() throws Exception {
        // Arrange - Generate keystore
        TestKeystoreGenerator.generateTestKeystore(
                keystorePath.toString(), "password", "testalias", "keypass");

        config.setKeystorePath(keystorePath.toString());
        config.setKeystorePassword("password");
        config.setKeyAlias("nonexistent"); // Wrong alias
        config.setKeyPassword("keypass");

        // Act & Assert - This kills VoidMethodCallMutator because if checkPrivateKey
        // is removed, we won't get the proper error handling
        assertThatThrownBy(
                        () -> {
                            TimestampService service = new TimestampService(config);
                            ReflectionTestUtils.invokeMethod(service, "initByKeystore");
                        })
                .isInstanceOf(Exception.class)
                .satisfies(
                        thrown -> {
                            // Should get specific error from checkPrivateKey
                            String message = thrown.getMessage();
                            Throwable cause = thrown.getCause();
                            boolean hasKeyError =
                                    message != null && message.contains("Private key not found");
                            boolean causeHasKeyError =
                                    cause != null
                                            && cause.getMessage() != null
                                            && cause.getMessage().contains("Private key not found");
                            assertThat(hasKeyError || causeHasKeyError)
                                    .as("Should detect missing private key through checkPrivateKey")
                                    .isTrue();
                        });
    }

    // ==================== checkCert() Tests ====================

    @Test
    void checkCert_shouldBeCalled_whenLoadingFromKeystore() throws Exception {
        // Arrange - Generate keystore with certificate
        TestKeystoreGenerator.generateTestKeystore(
                keystorePath.toString(), "password", "testalias", "keypass");

        config.setKeystorePath(keystorePath.toString());
        config.setKeystorePassword("password");
        config.setKeyAlias("testalias");
        config.setKeyPassword("keypass");

        // Act
        TimestampService service = new TimestampService(config);
        service.init();

        // Assert - Service works correctly (implies checkCert was called)
        assertThat(service.getSigningCertificate()).isNotNull();
    }

    // ==================== logCertInfo() Tests ====================

    @Test
    void logCertInfo_shouldBeCalled_whenLoadingFromKeystore() throws Exception {
        // Arrange - Generate keystore
        TestKeystoreGenerator.generateTestKeystore(
                keystorePath.toString(), "password", "testalias", "keypass");

        config.setKeystorePath(keystorePath.toString());
        config.setKeystorePassword("password");
        config.setKeyAlias("testalias");
        config.setKeyPassword("keypass");

        clearMemoryAppender();

        // Act
        TimestampService service = new TimestampService(config);
        service.init();

        // Assert - Verify logCertInfo was called (kills VoidMethodCallMutator)
        List<ILoggingEvent> events = getLoggedEvents();
        boolean hasCertInfoLog =
                events.stream()
                        .anyMatch(e -> e.getFormattedMessage().contains("Certificate subject:"));
        assertThat(hasCertInfoLog)
                .as("logCertInfo should have been called and logged certificate details")
                .isTrue();
    }

    @Test
    void logCertInfo_shouldBeCalledDuringUpdateSigningKey() throws Exception {
        // Arrange - Create a test PKCS12
        TestKeystoreGenerator.generateTestKeystore(
                keystorePath.toString(), "password", "testalias", "keypass");

        byte[] pkcs12Data = java.nio.file.Files.readAllBytes(keystorePath);

        // Create service with generated key first
        TimestampService service = new TimestampService(new TimeStampConfig());
        service.init();

        clearMemoryAppender();

        // Act
        service.updateSigningKey(pkcs12Data, "password", "keypass", "testalias");

        // Assert - Verify logCertInfo was called during update (kills VoidMethodCallMutator)
        List<ILoggingEvent> events = getLoggedEvents();
        boolean hasCertInfoLog =
                events.stream()
                        .anyMatch(e -> e.getFormattedMessage().contains("Certificate subject:"));
        assertThat(hasCertInfoLog)
                .as("logCertInfo should have been called during updateSigningKey")
                .isTrue();
    }

    // ==================== KeyPairGenerator.initialize() Tests ====================

    @Test
    void keyPairGeneratorInitialize_shouldBeCalled_whenGeneratingKey() throws Exception {
        // Arrange - Config with no keystore (will generate key)
        TimeStampConfig genConfig = new TimeStampConfig();
        genConfig.setKeySize(2048);

        clearMemoryAppender();

        // Act
        TimestampService service = new TimestampService(genConfig);
        service.init();

        // Assert - If initialize() was removed, the key generation might fail
        // We verify the service works correctly
        assertThat(service.getSigningCertificate()).isNotNull();

        // Also verify it logged the generation
        List<ILoggingEvent> events = getLoggedEvents();
        boolean hasGenerationLog =
                events.stream().anyMatch(e -> e.getFormattedMessage().contains("Generated new"));
        assertThat(hasGenerationLog).isTrue();
    }
}
