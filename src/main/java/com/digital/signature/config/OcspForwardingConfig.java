package com.digital.signature.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Startup defaults of the OCSP forwarding of requests without issuer profile ({@code
 * ocsp.forwarding.*}). The values can be changed at runtime through the web UI or {@code PUT
 * /api/ocsp/forwarding}; a restart restores these defaults.
 */
@Component
@ConfigurationProperties(prefix = "ocsp.forwarding")
public class OcspForwardingConfig {
    private boolean enabled;
    private String url;

    /** Returns whether forwarding is enabled at startup (default: false). */
    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(final boolean enabled) {
        this.enabled = enabled;
    }

    /** Returns the HTTP(S) URL of the other OCSP responder, or null when not configured. */
    public String getUrl() {
        return url;
    }

    public void setUrl(final String url) {
        this.url = url;
    }
}
