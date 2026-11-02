package com.digital.signature.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "timestamp")
public class TimeStampConfig {
    private String keyAlgorithm = "RSA";
    private int keySize = 2048;
    private String sigAlgo = "SHA256WithRSA";
    private String certSubject = "CN=Test Timestamp Authority, O=Digital Signature, C=HU";
    private String policyId = "1.3.6.1.4.1.13762.3";
    private int validityDays = 365;

    // PKCS12 Keystore configuration
    private String keystorePath;
    private String keystorePassword;
    private String keyAlias;
    private String keyPassword;

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public void setKeyAlgorithm(final String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
    }

    public int getKeySize() {
        return keySize;
    }

    public void setKeySize(final int keySize) {
        this.keySize = keySize;
    }

    public String getSignatureAlgorithm() {
        return sigAlgo;
    }

    public void setSignatureAlgorithm(final String sigAlgo) {
        this.sigAlgo = sigAlgo;
    }

    public String getCertificateSubject() {
        return certSubject;
    }

    public void setCertificateSubject(final String certSubject) {
        this.certSubject = certSubject;
    }

    public String getPolicyId() {
        return policyId;
    }

    public void setPolicyId(final String policyId) {
        this.policyId = policyId;
    }

    public int getValidityDays() {
        return validityDays;
    }

    public void setValidityDays(final int validityDays) {
        this.validityDays = validityDays;
    }

    public String getKeystorePath() {
        return keystorePath;
    }

    public void setKeystorePath(final String keystorePath) {
        this.keystorePath = keystorePath;
    }

    public String getKeystorePassword() {
        return keystorePassword;
    }

    public void setKeystorePassword(final String keystorePassword) {
        this.keystorePassword = keystorePassword;
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public void setKeyAlias(final String keyAlias) {
        this.keyAlias = keyAlias;
    }

    public String getKeyPassword() {
        return keyPassword;
    }

    public void setKeyPassword(final String keyPassword) {
        this.keyPassword = keyPassword;
    }

    public boolean isKeystoreConfigured() {
        return keystorePath != null && !keystorePath.isEmpty();
    }

    public boolean hasValidKeystoreConfig() {
        return isKeystoreConfigured() && keystorePassword != null && keyAlias != null;
    }
}
