package com.digital.signature.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.digital.signature.AbstractTest;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.MessageDigest;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class TimestampServiceUpdateKeyTest extends AbstractTest {

    @Autowired private TimestampService timestampService;

    private byte[] originalPkcs12Data;
    private String originalKeystorePassword = "testpass";
    private String originalKeyPassword = "testpass";
    private String originalKeyAlias = "testkey";

    @BeforeEach
    void setUp() throws Exception {
        originalPkcs12Data = createTestPkcs12File();
    }

    @Test
    void updateSigningKey_shouldUpdateKeySuccessfully_whenValidPkcs12Provided() throws Exception {
        // Act
        timestampService.updateSigningKey(
                originalPkcs12Data,
                originalKeystorePassword,
                originalKeyPassword,
                originalKeyAlias);

        // Assert - Verify that we can still generate valid timestamp responses with the new key
        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest("test-data".getBytes());
        TimeStampRequest request =
                reqGen.generate(NISTObjectIdentifiers.id_sha256, hash, BigInteger.valueOf(100));

        byte[] result = timestampService.generateTimestampResponse(request.getEncoded());
        assertThat(result).isNotNull().isNotEmpty();

        TimeStampResponse response = new TimeStampResponse(result);
        assertThat(response.getStatus()).isEqualTo(0);
        assertThat(response.getTimeStampToken()).isNotNull();
    }

    @Test
    void updateSigningKey_shouldUseKeystorePasswordAsKeyPassword_whenKeyPasswordNotProvided()
            throws Exception {
        // Act - Don't provide keyPassword, should default to keystorePassword
        timestampService.updateSigningKey(
                originalPkcs12Data, originalKeystorePassword, null, originalKeyAlias);

        // Assert - Should work with the default key password
        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest("test-data".getBytes());
        TimeStampRequest request =
                reqGen.generate(NISTObjectIdentifiers.id_sha256, hash, BigInteger.valueOf(100));

        byte[] result = timestampService.generateTimestampResponse(request.getEncoded());
        assertThat(result).isNotNull().isNotEmpty();

        TimeStampResponse response = new TimeStampResponse(result);
        assertThat(response.getStatus()).isEqualTo(0);
    }

    @Test
    void updateSigningKey_shouldFindFirstKey_whenKeyAliasNotProvided() throws Exception {
        // Act - Don't provide keyAlias, should find the first private key
        timestampService.updateSigningKey(
                originalPkcs12Data, originalKeystorePassword, originalKeyPassword, null);

        // Assert - Should work with auto-detected alias
        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest("test-data".getBytes());
        TimeStampRequest request =
                reqGen.generate(NISTObjectIdentifiers.id_sha256, hash, BigInteger.valueOf(100));

        byte[] result = timestampService.generateTimestampResponse(request.getEncoded());
        assertThat(result).isNotNull().isNotEmpty();

        TimeStampResponse response = new TimeStampResponse(result);
        assertThat(response.getStatus()).isEqualTo(0);
    }

    @Test
    void updateSigningKey_shouldExposeNewCertificate_whenValidPkcs12Provided() throws Exception {
        // Arrange - capture the certificate exposed before the update, and what the new
        // certificate's encoded bytes are expected to be
        byte[] certificateBeforeUpdate = timestampService.getSigningCertificate();

        KeyStore newKeystore = KeyStore.getInstance("PKCS12");
        try (java.io.ByteArrayInputStream bais =
                new java.io.ByteArrayInputStream(originalPkcs12Data)) {
            newKeystore.load(bais, originalKeystorePassword.toCharArray());
        }
        byte[] expectedCertificate = newKeystore.getCertificate(originalKeyAlias).getEncoded();

        // Act
        timestampService.updateSigningKey(
                originalPkcs12Data,
                originalKeystorePassword,
                originalKeyPassword,
                originalKeyAlias);

        // Assert - getSigningCertificate()/getSigningCertificateAsPem() must reflect the
        // newly loaded certificate, not the one that was active before the update.
        byte[] certificateAfterUpdate = timestampService.getSigningCertificate();
        assertThat(certificateAfterUpdate)
                .isEqualTo(expectedCertificate)
                .isNotEqualTo(certificateBeforeUpdate);

        String pem = timestampService.getSigningCertificateAsPem();
        byte[] decodedFromPem =
                java.util.Base64.getDecoder()
                        .decode(
                                pem.replace("-----BEGIN CERTIFICATE-----", "")
                                        .replace("-----END CERTIFICATE-----", "")
                                        .replace("\n", "")
                                        .trim());
        assertThat(decodedFromPem).isEqualTo(expectedCertificate);
    }

    @Test
    void updateSigningKey_shouldThrowException_whenInvalidPasswordProvided() {
        // Act & Assert
        assertThatThrownBy(
                        () ->
                                timestampService.updateSigningKey(
                                        originalPkcs12Data,
                                        "wrongpassword",
                                        originalKeyPassword,
                                        originalKeyAlias))
                .isInstanceOf(Exception.class);
    }

    @Test
    void updateSigningKey_shouldThrowException_whenInvalidKeyPasswordProvided() {
        // Act & Assert
        assertThatThrownBy(
                        () ->
                                timestampService.updateSigningKey(
                                        originalPkcs12Data,
                                        originalKeystorePassword,
                                        "wrongkeypassword",
                                        originalKeyAlias))
                .isInstanceOf(Exception.class);
    }

    @Test
    void updateSigningKey_shouldThrowException_whenInvalidKeyAliasProvided() {
        // Act & Assert
        assertThatThrownBy(
                        () ->
                                timestampService.updateSigningKey(
                                        originalPkcs12Data,
                                        originalKeystorePassword,
                                        originalKeyPassword,
                                        "nonexistentalias"))
                .isInstanceOf(Exception.class);
    }

    @Test
    void updateSigningKey_shouldThrowException_whenFileDoesNotContainPrivateKey() throws Exception {
        // Create a PKCS12 file with only certificates, no private keys
        byte[] certOnlyPkcs12Data = createCertOnlyPkcs12File();

        // Act & Assert
        assertThatThrownBy(
                        () ->
                                timestampService.updateSigningKey(
                                        certOnlyPkcs12Data,
                                        originalKeystorePassword,
                                        originalKeyPassword,
                                        null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("No private key found");
    }

    // Helper method to create a test PKCS12 file
    private byte[] createTestPkcs12File() throws Exception {
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(null, null);

        // Generate a key pair and self-signed certificate
        java.security.KeyPairGenerator keyPairGenerator =
                java.security.KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Create self-signed certificate
        java.security.cert.X509Certificate[] chain = new java.security.cert.X509Certificate[1];
        chain[0] = generateSelfSignedCertificate(keyPair);

        // Store the key and certificate
        keystore.setKeyEntry(
                originalKeyAlias, keyPair.getPrivate(), originalKeyPassword.toCharArray(), chain);

        // Save to byte array
        java.io.ByteArrayOutputStream outputStream = new java.io.ByteArrayOutputStream();
        keystore.store(outputStream, originalKeystorePassword.toCharArray());

        return outputStream.toByteArray();
    }

    // Helper method to create a PKCS12 file with only certificates
    private byte[] createCertOnlyPkcs12File() throws Exception {
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(null, null);

        // Generate a key pair and self-signed certificate
        java.security.KeyPairGenerator keyPairGenerator =
                java.security.KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Create self-signed certificate
        java.security.cert.X509Certificate cert = generateSelfSignedCertificate(keyPair);

        // Store only the certificate (no private key)
        keystore.setCertificateEntry("cert-only", cert);

        // Save to byte array
        java.io.ByteArrayOutputStream outputStream = new java.io.ByteArrayOutputStream();
        keystore.store(outputStream, originalKeystorePassword.toCharArray());

        return outputStream.toByteArray();
    }

    // Helper method to generate self-signed certificate with proper extensions for timestamping
    private java.security.cert.X509Certificate generateSelfSignedCertificate(
            java.security.KeyPair keyPair) throws Exception {
        java.security.cert.X509Certificate cert;
        try {
            String dn = "CN=Test Certificate, O=Digital Signature, C=HU";

            // Use BouncyCastle to generate self-signed certificate
            org.bouncycastle.asn1.x500.X500Name subject =
                    new org.bouncycastle.asn1.x500.X500Name(dn);
            java.math.BigInteger serial = java.math.BigInteger.valueOf(System.currentTimeMillis());
            java.util.Date notBefore = new java.util.Date();
            java.util.Date notAfter =
                    new java.util.Date(System.currentTimeMillis() + 365L * 24L * 60L * 60L * 1000L);

            org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder certBuilder =
                    new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                            subject, serial, notBefore, notAfter, subject, keyPair.getPublic());

            // Add required extensions for timestamping
            certBuilder.addExtension(
                    org.bouncycastle.asn1.x509.Extension.basicConstraints,
                    true,
                    new org.bouncycastle.asn1.x509.BasicConstraints(false));

            certBuilder.addExtension(
                    org.bouncycastle.asn1.x509.Extension.keyUsage,
                    true,
                    new org.bouncycastle.asn1.x509.KeyUsage(
                            org.bouncycastle.asn1.x509.KeyUsage.digitalSignature
                                    | org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation));

            certBuilder.addExtension(
                    org.bouncycastle.asn1.x509.Extension.extendedKeyUsage,
                    true,
                    new org.bouncycastle.asn1.x509.ExtendedKeyUsage(
                            org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_timeStamping));

            org.bouncycastle.operator.ContentSigner contentSigner =
                    new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256WithRSA")
                            .build(keyPair.getPrivate());
            org.bouncycastle.cert.X509CertificateHolder certHolder =
                    certBuilder.build(contentSigner);

            cert =
                    new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                            .getCertificate(certHolder);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate self-signed certificate", e);
        }
        return cert;
    }
}
