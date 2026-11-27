package com.digital.signature.config;

import com.digital.signature.service.OcspService;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

/** Applies the configured OCSP forwarding defaults to {@link OcspService} at startup. */
@Component
public class OcspForwardingInitializer {
    private final OcspService service;
    private final OcspForwardingConfig config;

    public OcspForwardingInitializer(final OcspService service, final OcspForwardingConfig config) {
        this.service = service;
        this.config = config;
    }

    /**
     * Applies {@code ocsp.forwarding.enabled} and {@code ocsp.forwarding.url}.
     *
     * @throws IllegalStateException if the configured values are invalid, so the server does not
     *     start with a wrong configuration
     */
    @PostConstruct
    public void apply() {
        try {
            service.setForwarding(new OcspService.Forwarding(config.isEnabled(), config.getUrl()));
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(
                    "Invalid ocsp.forwarding configuration: " + e.getMessage(), e);
        }
    }
}
