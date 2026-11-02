package com.digital.signature.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.digital.signature.AbstractTest;
import org.junit.jupiter.api.Test;

/** Tests for TimeStampConfig to improve mutation coverage. */
class TimeStampConfigTest extends AbstractTest {

    @Test
    void isKeystoreConfigured_shouldReturnFalse_whenKeystorePathIsNull() {
        // Arrange
        final TimeStampConfig config = new TimeStampConfig();
        config.setKeystorePath(null);

        // Act
        final boolean result = config.isKeystoreConfigured();

        // Assert
        assertThat(result).isFalse();
    }

    @Test
    void isKeystoreConfigured_shouldReturnFalse_whenKeystorePathIsEmpty() {
        // Arrange
        final TimeStampConfig config = new TimeStampConfig();
        config.setKeystorePath("");

        // Act
        final boolean result = config.isKeystoreConfigured();

        // Assert
        assertThat(result).isFalse();
    }

    @Test
    void isKeystoreConfigured_shouldReturnTrue_whenKeystorePathIsSet() {
        // Arrange
        final TimeStampConfig config = new TimeStampConfig();
        config.setKeystorePath("/path/to/keystore.p12");

        // Act
        final boolean result = config.isKeystoreConfigured();

        // Assert
        assertThat(result).isTrue();
    }

    @Test
    void hasValidKeystoreConfig_shouldReturnFalse_whenKeystoreNotConfigured() {
        // Arrange
        final TimeStampConfig config = new TimeStampConfig();
        config.setKeystorePath(null);
        config.setKeystorePassword("password");
        config.setKeyAlias("alias");

        // Act
        final boolean result = config.hasValidKeystoreConfig();

        // Assert
        assertThat(result).isFalse();
    }

    @Test
    void hasValidKeystoreConfig_shouldReturnFalse_whenPasswordIsNull() {
        // Arrange
        final TimeStampConfig config = new TimeStampConfig();
        config.setKeystorePath("/path/to/keystore.p12");
        config.setKeystorePassword(null);
        config.setKeyAlias("alias");

        // Act
        final boolean result = config.hasValidKeystoreConfig();

        // Assert
        assertThat(result).isFalse();
    }

    @Test
    void hasValidKeystoreConfig_shouldReturnFalse_whenKeyAliasIsNull() {
        // Arrange
        final TimeStampConfig config = new TimeStampConfig();
        config.setKeystorePath("/path/to/keystore.p12");
        config.setKeystorePassword("password");
        config.setKeyAlias(null);

        // Act
        final boolean result = config.hasValidKeystoreConfig();

        // Assert
        assertThat(result).isFalse();
    }

    @Test
    void hasValidKeystoreConfig_shouldReturnTrue_whenAllFieldsAreSet() {
        // Arrange
        final TimeStampConfig config = new TimeStampConfig();
        config.setKeystorePath("/path/to/keystore.p12");
        config.setKeystorePassword("password");
        config.setKeyAlias("alias");

        // Act
        final boolean result = config.hasValidKeystoreConfig();

        // Assert
        assertThat(result).isTrue();
    }

    @Test
    void gettersAndSetters_shouldWorkCorrectly() {
        // Arrange
        final TimeStampConfig config = new TimeStampConfig();

        // Act & Assert
        config.setKeyAlgorithm("EC");
        assertThat(config.getKeyAlgorithm()).isEqualTo("EC");

        config.setKeySize(4096);
        assertThat(config.getKeySize()).isEqualTo(4096);

        config.setSignatureAlgorithm("SHA512WithECDSA");
        assertThat(config.getSignatureAlgorithm()).isEqualTo("SHA512WithECDSA");

        config.setCertificateSubject("CN=Test");
        assertThat(config.getCertificateSubject()).isEqualTo("CN=Test");

        config.setPolicyId("1.2.3");
        assertThat(config.getPolicyId()).isEqualTo("1.2.3");

        config.setValidityDays(730);
        assertThat(config.getValidityDays()).isEqualTo(730);

        config.setKeyPassword("keypass");
        assertThat(config.getKeyPassword()).isEqualTo("keypass");
    }
}
