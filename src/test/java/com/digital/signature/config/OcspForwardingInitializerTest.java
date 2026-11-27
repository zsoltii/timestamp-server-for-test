package com.digital.signature.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.digital.signature.service.OcspService;
import org.junit.jupiter.api.Test;

class OcspForwardingInitializerTest {
    private final OcspService service = new OcspService();
    private final OcspForwardingConfig config = new OcspForwardingConfig();

    @Test
    void defaultsKeepForwardingDisabled() {
        new OcspForwardingInitializer(service, config).apply();

        assertThat(config.isEnabled()).isFalse();
        assertThat(config.getUrl()).isNull();
        assertThat(service.forwarding()).isEqualTo(new OcspService.Forwarding(false, null));
    }

    @Test
    void appliesConfiguredEnabledForwarding() {
        config.setEnabled(true);
        config.setUrl("http://ocsp.example.com/ocsp");

        new OcspForwardingInitializer(service, config).apply();

        assertThat(service.forwarding())
                .isEqualTo(new OcspService.Forwarding(true, "http://ocsp.example.com/ocsp"));
    }

    @Test
    void appliesConfiguredUrlWhileDisabled() {
        config.setUrl("https://ocsp.example.com/ocsp");

        new OcspForwardingInitializer(service, config).apply();

        assertThat(service.forwarding())
                .isEqualTo(new OcspService.Forwarding(false, "https://ocsp.example.com/ocsp"));
    }

    @Test
    void configuredDefaultCanBeOverriddenAtRuntime() {
        config.setEnabled(true);
        config.setUrl("http://ocsp.example.com/ocsp");
        new OcspForwardingInitializer(service, config).apply();

        service.setForwarding(new OcspService.Forwarding(false, "http://other.example/ocsp"));

        assertThat(service.forwarding())
                .isEqualTo(new OcspService.Forwarding(false, "http://other.example/ocsp"));
        assertThat(config.isEnabled()).isTrue();
    }

    @Test
    void enabledWithoutUrlFailsTheStartup() {
        config.setEnabled(true);

        assertThatThrownBy(() -> new OcspForwardingInitializer(service, config).apply())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("ocsp.forwarding");
    }

    @Test
    void invalidUrlFailsTheStartup() {
        config.setUrl("ftp://ocsp.example.com");

        assertThatThrownBy(() -> new OcspForwardingInitializer(service, config).apply())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("http or https");
    }
}
