package com.digital.signature.util;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Utility class to generate test PKCS12 keystores for unit testing. */
public class TestKeystoreGenerator {

    /** Generate test keystore with RSA key */
    public static void generateTestKeystore(
            String keystorePath, String keystorePassword, String keyAlias, String keyPassword)
            throws Exception {
        generateTestKeystore(
                keystorePath,
                keystorePassword,
                keyAlias,
                keyPassword,
                "RSA",
                2048,
                "SHA256WithRSA");
    }

    /** Generate test keystore with EC key */
    public static void generateTestKeystoreWithEC(
            String keystorePath, String keystorePassword, String keyAlias, String keyPassword)
            throws Exception {
        generateTestKeystore(
                keystorePath,
                keystorePassword,
                keyAlias,
                keyPassword,
                "EC",
                256,
                "SHA256withECDSA");
    }

    /** Generate test keystore with specified key algorithm */
    public static void generateTestKeystore(
            String keystorePath,
            String keystorePassword,
            String keyAlias,
            String keyPassword,
            String keyAlgorithm,
            int keySize,
            String signatureAlgorithm)
            throws Exception {

        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm);
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Create self-signed certificate
        X500Name subject = new X500Name("CN=Test Timestamp Authority, O=Test, C=HU");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = Date.from(Instant.now());
        Date notAfter = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));

        JcaX509v3CertificateBuilder certBuilder =
                new JcaX509v3CertificateBuilder(
                        subject, serial, notBefore, notAfter, subject, keyPair.getPublic());

        // Add extensions
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certBuilder.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
        certBuilder.addExtension(
                Extension.extendedKeyUsage,
                true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

        ContentSigner contentSigner =
                new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());
        X509Certificate certificate =
                new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));

        // Create PKCS12 keystore
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(null, null);

        // Add key and certificate to keystore
        keystore.setKeyEntry(
                keyAlias,
                keyPair.getPrivate(),
                keyPassword.toCharArray(),
                new Certificate[] {certificate});

        // Save keystore to file
        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
            keystore.store(fos, keystorePassword.toCharArray());
        }
    }

    public static void generateCorruptedKeystore(String keystorePath) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
            fos.write("This is not a valid PKCS12 file".getBytes());
        }
    }

    public static void main(String[] args) throws Exception {
        // Generate test keystore for manual testing
        generateTestKeystore(
                "src/test/resources/test-keystore.p12", "testPassword", "testKey", "keyPassword");
        System.out.println("Test keystore generated at: src/test/resources/test-keystore.p12");
    }
}
