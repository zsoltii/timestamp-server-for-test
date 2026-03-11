package com.digital.signature.service;

import com.digital.signature.config.TimeStampConfig;
import jakarta.annotation.PostConstruct;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class TimestampService {

    private static final Logger logger = LoggerFactory.getLogger(TimestampService.class);

    private TimeStampResponseGenerator timeStampResponseGenerator;
    private X509CertificateHolder signingCertificate;

    @Autowired private TimeStampConfig config;

    @PostConstruct
    public void init() {
        try {
            PrivateKey privateKey;

            // Check if PKCS12 keystore is configured
            if (StringUtils.hasText(config.getKeystorePath())) {
                logger.info(
                        "Loading key and certificate from PKCS12 keystore: {}",
                        config.getKeystorePath());

                // Load PKCS12 keystore
                KeyStore keystore = KeyStore.getInstance("PKCS12");
                try (FileInputStream fis = new FileInputStream(config.getKeystorePath())) {
                    keystore.load(fis, config.getKeystorePassword().toCharArray());
                }

                // Get private key
                String keyPassword =
                        StringUtils.hasText(config.getKeyPassword())
                                ? config.getKeyPassword()
                                : config.getKeystorePassword();

                privateKey =
                        (PrivateKey)
                                keystore.getKey(config.getKeyAlias(), keyPassword.toCharArray());

                if (privateKey == null) {
                    throw new IllegalStateException(
                            "Private key not found in keystore with alias: "
                                    + config.getKeyAlias());
                }

                // Get certificate
                Certificate cert = keystore.getCertificate(config.getKeyAlias());
                if (cert == null) {
                    throw new IllegalStateException(
                            "Certificate not found in keystore with alias: "
                                    + config.getKeyAlias());
                }

                // Convert X509Certificate to X509CertificateHolder
                X509Certificate x509Cert = (X509Certificate) cert;
                signingCertificate = new X509CertificateHolder(x509Cert.getEncoded());

                logger.info("Successfully loaded key and certificate from keystore");
                logger.info(
                        "Certificate subject: {}", x509Cert.getSubjectX500Principal().getName());
                logger.info(
                        "Certificate valid from: {} to: {}",
                        x509Cert.getNotBefore(),
                        x509Cert.getNotAfter());
            } else {
                logger.info(
                        "No keystore configured, generating new key pair and self-signed certificate");

                // 1. Kulcspár generálás (RSA 2048) teszt célra
                KeyPairGenerator keyPairGenerator =
                        KeyPairGenerator.getInstance(config.getKeyAlgorithm());
                keyPairGenerator.initialize(config.getKeySize());
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                privateKey = keyPair.getPrivate();

                // 2. Önaláírt tanúsítvány generálás
                X500Name subject = new X500Name(config.getCertificateSubject());
                BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
                Date notBefore = Date.from(Instant.now());
                Date notAfter =
                        Date.from(Instant.now().plus(config.getValidityDays(), ChronoUnit.DAYS));

                JcaX509v3CertificateBuilder certBuilder =
                        new JcaX509v3CertificateBuilder(
                                subject, serial, notBefore, notAfter, subject, keyPair.getPublic());

                // Kiterjesztések hozzáadása a szabványos timestampinghez
                certBuilder.addExtension(
                        Extension.basicConstraints, true, new BasicConstraints(false)); // Nem CA
                certBuilder.addExtension(
                        Extension.keyUsage,
                        true,
                        new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
                certBuilder.addExtension(
                        Extension.extendedKeyUsage,
                        true,
                        new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

                ContentSigner contentSigner =
                        new JcaContentSignerBuilder(config.getSignatureAlgorithm())
                                .build(privateKey);
                signingCertificate = certBuilder.build(contentSigner);

                logger.info("Generated new self-signed certificate");
            }

            // Create ContentSigner with the private key
            ContentSigner contentSigner =
                    new JcaContentSignerBuilder(config.getSignatureAlgorithm()).build(privateKey);

            // 3. TimeStampResponseGenerator inicializálás
            ASN1ObjectIdentifier policyId = new ASN1ObjectIdentifier(config.getPolicyId());

            DigestCalculatorProvider digestCalculatorProvider =
                    new JcaDigestCalculatorProviderBuilder().build();

            // SignerInfoGenerator létrehozása
            SignerInfoGenerator signerInfoGenerator =
                    new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider)
                            .build(contentSigner, signingCertificate);

            // DigestCalculator létrehozása (SHA-1 a timestamp tokenhez)
            DigestCalculator digestCalculator =
                    digestCalculatorProvider.get(
                            new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

            TimeStampTokenGenerator tokenGenerator =
                    new TimeStampTokenGenerator(signerInfoGenerator, digestCalculator, policyId);

            // Tanúsítványok hozzáadása Store-ként
            List<X509CertificateHolder> certs = new ArrayList<>();
            certs.add(signingCertificate);
            JcaCertStore certStore = new JcaCertStore(certs);
            tokenGenerator.addCertificates(certStore);

            Set<ASN1ObjectIdentifier> acceptedAlgorithms = new HashSet<>();
            acceptedAlgorithms.add(NISTObjectIdentifiers.id_sha256);
            acceptedAlgorithms.add(NISTObjectIdentifiers.id_sha512);
            acceptedAlgorithms.add(OIWObjectIdentifiers.idSHA1);

            // A konstruktor Set<String>-et vár az algoritmus OID-khoz
            Set<String> acceptedAlgorithmOids =
                    acceptedAlgorithms.stream()
                            .map(ASN1ObjectIdentifier::getId)
                            .collect(Collectors.toSet());

            // Elfogadott policy-k definiálása
            Set<String> acceptedPolicies = new HashSet<>();
            acceptedPolicies.add(policyId.getId());

            timeStampResponseGenerator =
                    new TimeStampResponseGenerator(
                            tokenGenerator, acceptedAlgorithmOids, acceptedPolicies);

        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize TimestampService", e);
        }
    }

    /** Generate RFC 3161 timestamp response */
    public byte[] generateTimestampResponse(byte[] requestBytes) {
        try {
            TimeStampRequest request = new TimeStampRequest(requestBytes);

            // Itt lehetne validálni a request-et (pl. algoritmus, policy)

            TimeStampResponse response =
                    timeStampResponseGenerator.generate(
                            request, BigInteger.valueOf(System.currentTimeMillis()), new Date());

            return response.getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Generate simple ISO 8601 formatted timestamp */
    public String generateSimpleTimestamp() {
        return Instant.now().toString();
    }

    /** Generate Unix timestamp (seconds since epoch) */
    public long generateUnixTimestamp() {
        return Instant.now().getEpochSecond();
    }

    /** Get the current signing certificate in DER format */
    public byte[] getSigningCertificate() throws Exception {
        if (signingCertificate == null) {
            throw new IllegalStateException("Signing certificate not initialized");
        }
        return signingCertificate.getEncoded();
    }

    /** Get the current signing certificate in PEM format */
    public String getSigningCertificateAsPem() throws Exception {
        byte[] derCertificate = getSigningCertificate();
        return convertDerToPem(derCertificate);
    }

    /** Convert DER encoded certificate to PEM format */
    private String convertDerToPem(byte[] derBytes) {
        String base64 = java.util.Base64.getEncoder().encodeToString(derBytes);
        // Wrap base64 content into 64-character lines
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN CERTIFICATE-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            int end = Math.min(i + 64, base64.length());
            pem.append(base64, i, end).append("\n");
        }
        pem.append("-----END CERTIFICATE-----");
        return pem.toString();
    }

    /**
     * Update the signing key with a new PKCS12 keystore
     *
     * @param pkcs12Data The PKCS12 file data
     * @param keystorePassword The password for the PKCS12 keystore
     * @param keyPassword The password for the private key (optional, defaults to keystorePassword)
     * @param keyAlias The alias of the key in the keystore (optional, defaults to first key found)
     * @throws IllegalArgumentException if the input parameters are invalid
     * @throws IllegalStateException if the key update fails due to internal error
     */
    public synchronized void updateSigningKey(
            byte[] pkcs12Data, String keystorePassword, String keyPassword, String keyAlias) {
        try {
            logger.info("Updating signing key with new PKCS12 keystore");

            // Load the new PKCS12 keystore
            KeyStore newKeystore = KeyStore.getInstance("PKCS12");
            newKeystore.load(
                    new java.io.ByteArrayInputStream(pkcs12Data), keystorePassword.toCharArray());

            // Use keystorePassword as default if keyPassword is not provided
            String effectiveKeyPassword =
                    keyPassword != null && !keyPassword.isEmpty() ? keyPassword : keystorePassword;

            // Find the key alias if not provided
            String effectiveKeyAlias = keyAlias;
            if (effectiveKeyAlias == null || effectiveKeyAlias.isEmpty()) {
                // Try to find the first private key entry
                java.util.Enumeration<String> aliases = newKeystore.aliases();
                while (aliases.hasMoreElements() && effectiveKeyAlias == null) {
                    String alias = aliases.nextElement();
                    if (newKeystore.isKeyEntry(alias)) {
                        effectiveKeyAlias = alias;
                    }
                }

                if (effectiveKeyAlias == null) {
                    throw new IllegalArgumentException("No private key found in the PKCS12 file");
                }
            }

            // Get private key
            PrivateKey newPrivateKey =
                    (PrivateKey)
                            newKeystore.getKey(
                                    effectiveKeyAlias, effectiveKeyPassword.toCharArray());
            if (newPrivateKey == null) {
                throw new IllegalArgumentException(
                        "Private key not found with alias: " + effectiveKeyAlias);
            }

            // Get certificate
            Certificate newCert = newKeystore.getCertificate(effectiveKeyAlias);
            if (newCert == null) {
                throw new IllegalArgumentException(
                        "Certificate not found with alias: " + effectiveKeyAlias);
            }

            // Convert X509Certificate to X509CertificateHolder
            X509Certificate x509Cert = (X509Certificate) newCert;
            X509CertificateHolder newCertificateHolder =
                    new X509CertificateHolder(x509Cert.getEncoded());

            logger.info("Successfully loaded new key and certificate from PKCS12");
            logger.info("Certificate subject: {}", x509Cert.getSubjectX500Principal().getName());
            logger.info(
                    "Certificate valid from: {} to: {}",
                    x509Cert.getNotBefore(),
                    x509Cert.getNotAfter());

            // Update the TimeStampResponseGenerator with the new key and certificate
            ContentSigner newContentSigner =
                    new JcaContentSignerBuilder(config.getSignatureAlgorithm())
                            .build(newPrivateKey);

            DigestCalculatorProvider digestCalculatorProvider =
                    new JcaDigestCalculatorProviderBuilder().build();
            SignerInfoGenerator newSignerInfoGenerator =
                    new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider)
                            .build(newContentSigner, newCertificateHolder);

            DigestCalculator digestCalculator =
                    digestCalculatorProvider.get(
                            new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

            TimeStampTokenGenerator newTokenGenerator =
                    new TimeStampTokenGenerator(
                            newSignerInfoGenerator,
                            digestCalculator,
                            new ASN1ObjectIdentifier(config.getPolicyId()));

            // Add certificates to store
            List<X509CertificateHolder> certs = new ArrayList<>();
            certs.add(newCertificateHolder);
            JcaCertStore certStore = new JcaCertStore(certs);
            newTokenGenerator.addCertificates(certStore);

            Set<ASN1ObjectIdentifier> acceptedAlgorithms = new HashSet<>();
            acceptedAlgorithms.add(NISTObjectIdentifiers.id_sha256);
            acceptedAlgorithms.add(NISTObjectIdentifiers.id_sha512);
            acceptedAlgorithms.add(OIWObjectIdentifiers.idSHA1);

            Set<String> acceptedAlgorithmOids =
                    acceptedAlgorithms.stream()
                            .map(ASN1ObjectIdentifier::getId)
                            .collect(Collectors.toSet());

            Set<String> acceptedPolicies = new HashSet<>();
            acceptedPolicies.add(config.getPolicyId());

            timeStampResponseGenerator =
                    new TimeStampResponseGenerator(
                            newTokenGenerator, acceptedAlgorithmOids, acceptedPolicies);

            logger.info("Successfully updated TimeStampResponseGenerator with new signing key");
        } catch (IllegalArgumentException e) {
            logger.warn("Invalid input for key update: {}", e.getMessage());
            throw e; // Re-throw for ControllerAdvice to handle
        } catch (Exception e) {
            logger.error("Failed to update signing key", e);
            throw new IllegalStateException("Failed to update signing key: " + e.getMessage(), e);
        }
    }
}
