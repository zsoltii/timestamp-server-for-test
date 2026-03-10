package com.digital.signature.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class TimeStampConfigTest {

    @Test
    void defaultValues_shouldBeSet() {
        TimeStampConfig config = new TimeStampConfig();

        assertThat(config.getKeyAlgorithm()).isEqualTo("RSA");
        assertThat(config.getKeySize()).isEqualTo(2048);
        assertThat(config.getSignatureAlgorithm()).isEqualTo("SHA256WithRSA");
        assertThat(config.getCertificateSubject())
                .isEqualTo("CN=Test Timestamp Authority, O=Digital Signature, C=HU");
        assertThat(config.getPolicyId()).isEqualTo("1.3.6.1.4.1.13762.3");
        assertThat(config.getValidityDays()).isEqualTo(365);
    }

    @Test
    void settersAndGetters_shouldWork() {
        TimeStampConfig config = new TimeStampConfig();

        config.setCertificateSubject("CN=New Subject");
        assertThat(config.getCertificateSubject()).isEqualTo("CN=New Subject");

        config.setValidityDays(730);
        assertThat(config.getValidityDays()).isEqualTo(730);
    }
}
