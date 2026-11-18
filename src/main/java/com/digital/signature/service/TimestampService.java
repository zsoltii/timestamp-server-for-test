package com.digital.signature.service;

import com.digital.signature.config.TimeStampConfig;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class TimestampService {

    private static final Logger LOGGER = LoggerFactory.getLogger(TimestampService.class);

    private static final Pattern TIME_PATTERN =
            Pattern.compile(
                    "(?<date>\\d{4}-\\d{2}-\\d{2})[ T](?<time>\\d{2}:\\d{2}:\\d{2})"
                            + "(?:\\s*(?<offset>[+-]\\d{2}(?::?\\d{2})?)"
                            + "|\\s+(?<spaceOffset>\\d{2}(?::?\\d{2})?)"
                            + "|\\s*(?<zone>[A-Za-z][A-Za-z0-9_+\\-/:]*))?");

    /**
     * Zone abbreviations that are not time-zone region ids. Only unambiguous ones are listed, an
     * abbreviation like CST (US, China, Cuba) is rejected instead of guessed.
     */
    private static final Map<String, ZoneOffset> ZONE_ABBREVIATIONS =
            Map.ofEntries(
                    Map.entry("Z", ZoneOffset.UTC),
                    Map.entry("UTC", ZoneOffset.UTC),
                    Map.entry("UT", ZoneOffset.UTC),
                    Map.entry("GMT", ZoneOffset.UTC),
                    Map.entry("WET", ZoneOffset.UTC),
                    Map.entry("WEST", ZoneOffset.ofHours(1)),
                    Map.entry("CET", ZoneOffset.ofHours(1)),
                    Map.entry("CEST", ZoneOffset.ofHours(2)),
                    Map.entry("EET", ZoneOffset.ofHours(2)),
                    Map.entry("EEST", ZoneOffset.ofHours(3)));

    private final AtomicReference<Instant> fixedTime = new AtomicReference<>();

    private TimeStampResponseGenerator responseGen;
    private X509CertificateHolder signCert;

    private final TimeStampConfig config;

    @Autowired
    public TimestampService(final TimeStampConfig config) {
        this.config = config;
    }

    @PostConstruct
    public void init() {
        try {
            final PrivateKey privateKey = initPrivateKey();

            // TimeStampResponseGenerator inicializálása
            final ContentSigner signer =
                    new JcaContentSignerBuilder(config.getSignatureAlgorithm()).build(privateKey);

            final DigestCalculatorProvider digestProvider =
                    new JcaDigestCalculatorProviderBuilder().build();
            final SignerInfoGenerator signerInfoGen =
                    new JcaSignerInfoGeneratorBuilder(digestProvider).build(signer, signCert);

            final DigestCalculator digestCalc =
                    digestProvider.get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

            final TimeStampTokenGenerator tokenGenerator =
                    new TimeStampTokenGenerator(
                            signerInfoGen,
                            digestCalc,
                            new ASN1ObjectIdentifier(config.getPolicyId()));

            // Tanúsítványok hozzáadása Store-ként
            final List<X509CertificateHolder> certs = new ArrayList<>();
            certs.add(signCert);
            final JcaCertStore certStore = new JcaCertStore(certs);
            tokenGenerator.addCertificates(certStore);

            final Set<ASN1ObjectIdentifier> algos = new HashSet<>();
            algos.add(NISTObjectIdentifiers.id_sha256);
            algos.add(NISTObjectIdentifiers.id_sha512);
            algos.add(OIWObjectIdentifiers.idSHA1);

            final Set<String> algoOids =
                    algos.stream().map(ASN1ObjectIdentifier::getId).collect(Collectors.toSet());

            final Set<String> policies = new HashSet<>();
            policies.add(config.getPolicyId());

            responseGen = new TimeStampResponseGenerator(tokenGenerator, algoOids, policies);

        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize TimestampService", e);
        }
    }

    private PrivateKey initPrivateKey()
            throws KeyStoreException,
                    IOException,
                    NoSuchAlgorithmException,
                    CertificateException,
                    UnrecoverableKeyException,
                    OperatorCreationException {
        final PrivateKey privateKey;

        // Check if PKCS12 keystore is configured
        if (StringUtils.hasText(config.getKeystorePath())) {
            privateKey = initByKeystore();
        } else {
            privateKey = initWithGenerateKey();
        }
        return privateKey;
    }

    private PrivateKey initWithGenerateKey()
            throws NoSuchAlgorithmException, CertIOException, OperatorCreationException {
        final PrivateKey privateKey;
        logGenerateNewCertificate(
                "No keystore configured, generating new key pair and self-signed certificate");

        // 1. Kulcspár generálás (RSA 2048) teszt célra
        final KeyPairGenerator keyPairGenerator =
                KeyPairGenerator.getInstance(config.getKeyAlgorithm());
        keyPairGenerator.initialize(config.getKeySize());
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();
        privateKey = keyPair.getPrivate();

        // 2. Önaláírt tanúsítvány generálás
        final X500Name subject = new X500Name(config.getCertificateSubject());
        final BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        final Instant now = Instant.now();

        final JcaX509v3CertificateBuilder certBuilder =
                new JcaX509v3CertificateBuilder(
                        subject,
                        serial,
                        Date.from(now),
                        Date.from(now.plus(config.getValidityDays(), ChronoUnit.DAYS)),
                        subject,
                        keyPair.getPublic());

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

        final ContentSigner contentSigner =
                new JcaContentSignerBuilder(config.getSignatureAlgorithm()).build(privateKey);
        signCert = certBuilder.build(contentSigner);

        logGenerateNewCertificate("Generated new self-signed certificate");
        return privateKey;
    }

    private static void logGeneratedTimestamp(final Instant genTime) {
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("Generating timestamp with time: {}", genTime);
        }
    }

    private static void logGenerateNewCertificate(final String msg) {
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info(msg);
        }
    }

    private @NonNull PrivateKey initByKeystore()
            throws KeyStoreException,
                    IOException,
                    NoSuchAlgorithmException,
                    CertificateException,
                    UnrecoverableKeyException {
        final PrivateKey privateKey;
        // Validate required fields
        checkConfig();

        logKeystorePath();

        // Load PKCS12 keystore
        final KeyStore keystore = KeyStore.getInstance("PKCS12");
        try (InputStream fis = Files.newInputStream(Paths.get(config.getKeystorePath()))) {
            keystore.load(fis, config.getKeystorePassword().toCharArray());
        }

        // Get private key
        final String keyPassword =
                StringUtils.hasText(config.getKeyPassword())
                        ? config.getKeyPassword()
                        : config.getKeystorePassword();

        privateKey = (PrivateKey) keystore.getKey(config.getKeyAlias(), keyPassword.toCharArray());

        checkPrivateKey(privateKey);

        // Get certificate
        final Certificate cert = keystore.getCertificate(config.getKeyAlias());
        checkCert(cert);

        // Convert X509Certificate to X509CertificateHolder
        final X509Certificate x509Cert = (X509Certificate) cert;
        signCert = new X509CertificateHolder(x509Cert.getEncoded());

        logCertInfo("Successfully loaded key and certificate from keystore", x509Cert);
        return privateKey;
    }

    private void checkCert(final Certificate cert) {
        if (cert == null) {
            throw new IllegalStateException(
                    "Certificate not found in keystore with alias: " + config.getKeyAlias());
        }
    }

    private void checkPrivateKey(final PrivateKey privateKey) {
        if (privateKey == null) {
            throw new IllegalStateException(
                    "Private key not found in keystore with alias: " + config.getKeyAlias());
        }
    }

    private void checkConfig() {
        if (config.getKeystorePassword() == null) {
            throw new IllegalArgumentException("Keystore password cannot be null");
        }
        if (config.getKeyAlias() == null) {
            throw new IllegalArgumentException("Key alias cannot be null");
        }
    }

    private void logKeystorePath() {
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info(
                    "Loading key and certificate from PKCS12 keystore: {}",
                    config.getKeystorePath());
        }
    }

    private static void logCertInfo(final String msg, final X509Certificate x509Cert) {
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info(msg);
            LOGGER.info("Certificate subject: {}", x509Cert.getSubjectX500Principal().getName());
            LOGGER.info(
                    "Certificate valid from: {} to: {}",
                    x509Cert.getNotBefore(),
                    x509Cert.getNotAfter());
        }
    }

    /**
     * Generate RFC 3161 timestamp response stamped with the fixed time when one is set, otherwise
     * with the current time
     */
    public byte[] generateTimestampResponse(final byte[] requestBytes) {
        final Instant fixed = fixedTime.get();
        return generateTimestampResponse(requestBytes, fixed != null ? fixed : Instant.now());
    }

    /**
     * Set the time that is written into every timestamp generated by {@link
     * #generateTimestampResponse(byte[])}, until it is changed or cleared. The setting is kept in
     * memory only.
     *
     * @param time the time in the format accepted by {@link #parseTimestampTime(String)}, a blank
     *     value clears the fixed time so the current time is used again
     * @return the fixed time, or null when it has been cleared
     * @throws IllegalArgumentException if the text is not a valid time
     */
    public Instant updateFixedTime(final String time) {
        final Instant newFixedTime = StringUtils.hasText(time) ? parseGivenTime(time) : null;
        fixedTime.set(newFixedTime);
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("Fixed timestamp time set to: {}", newFixedTime);
        }
        return newFixedTime;
    }

    /** Get the fixed timestamp time, or null when the current time is used */
    public Instant getFixedTime() {
        return fixedTime.get();
    }

    /**
     * Generate RFC 3161 timestamp response stamped with the given time, which may be in the past or
     * in the future.
     *
     * @param requestBytes the DER encoded timestamp request
     * @param genTime the time to write into the timestamp token
     * @return the DER encoded timestamp response
     * @throws IllegalArgumentException if the request or the time is null
     * @throws IllegalStateException if the response cannot be generated
     */
    public byte[] generateTimestampResponse(final byte[] requestBytes, final Instant genTime) {
        if (requestBytes == null) {
            throw new IllegalArgumentException("Request bytes cannot be null");
        }
        if (genTime == null) {
            throw new IllegalArgumentException("Timestamp time cannot be null");
        }
        try {
            final TimeStampRequest request = new TimeStampRequest(requestBytes);
            logGeneratedTimestamp(genTime);

            final TimeStampResponse response =
                    responseGen.generate(
                            request,
                            BigInteger.valueOf(System.currentTimeMillis()),
                            Date.from(genTime));

            return response.getEncoded();
        } catch (org.bouncycastle.tsp.TSPException | IOException e) {
            throw new IllegalStateException("Failed to generate timestamp response", e);
        }
    }

    /**
     * Parse a timestamp time in the {@code yyyy-MM-dd HH:mm:ssZ} format. The zone is optional, UTC
     * is used when it is omitted, and can be:
     *
     * <ul>
     *   <li>an offset: {@code Z}, {@code +0200}, {@code +02:00} or {@code +02}
     *   <li>a zone abbreviation: {@code UTC}, {@code GMT}, {@code CET}, {@code CEST}, {@code EET},
     *       {@code EEST}, {@code WET} or {@code WEST}, always with its fixed offset
     *   <li>a time-zone region id such as {@code Europe/Budapest}, with its daylight saving rules
     * </ul>
     *
     * A {@code T} is accepted instead of the space between date and time, and spaces are allowed
     * before the zone. A space in place of the offset's {@code +} sign is tolerated, because an
     * unencoded {@code +} in a URL query becomes a space.
     *
     * @param time the time text, blank means the current time
     * @return the parsed instant
     * @throws IllegalArgumentException if the text is not a valid time
     */
    public Instant parseTimestampTime(final String time) {
        return StringUtils.hasText(time) ? parseGivenTime(time) : Instant.now();
    }

    private static Instant parseGivenTime(final String time) {
        final Matcher matcher = TIME_PATTERN.matcher(time.strip());
        if (!matcher.matches()) {
            throw new IllegalArgumentException(
                    "Invalid time '" + time + "', expected format: yyyy-MM-dd HH:mm:ssZ");
        }
        try {
            final LocalDateTime localDateTime =
                    LocalDateTime.parse(matcher.group("date") + "T" + matcher.group("time"));
            return localDateTime.atZone(parseZone(matcher)).toInstant();
        } catch (DateTimeException e) {
            throw new IllegalArgumentException("Invalid time '" + time + "': " + e.getMessage(), e);
        }
    }

    private static ZoneId parseZone(final Matcher matcher) {
        final ZoneId zone;
        if (matcher.group("offset") != null) {
            zone = ZoneOffset.of(matcher.group("offset"));
        } else if (matcher.group("spaceOffset") != null) {
            zone = ZoneOffset.of("+" + matcher.group("spaceOffset"));
        } else if (matcher.group("zone") != null) {
            zone = zoneByName(matcher.group("zone"));
        } else {
            zone = ZoneOffset.UTC;
        }
        return zone;
    }

    private static ZoneId zoneByName(final String name) {
        final ZoneId abbreviation = ZONE_ABBREVIATIONS.get(name.toUpperCase(Locale.ROOT));
        return abbreviation != null ? abbreviation : ZoneId.of(name);
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
        if (signCert == null) {
            throw new IllegalStateException("Signing certificate not initialized");
        }
        return signCert.getEncoded();
    }

    /** Get the current signing certificate in PEM format */
    public String getSigningCertificateAsPem() throws Exception {
        final byte[] derCertificate = getSigningCertificate();
        return convertDerToPem(derCertificate);
    }

    /** Convert DER encoded certificate to PEM format */
    private String convertDerToPem(final byte[] derBytes) {
        final String base64 = Base64.getEncoder().encodeToString(derBytes);
        final int estimatedSize = base64.length() + 64; // Base64 + headers + newlines
        final StringBuilder pem = new StringBuilder(estimatedSize);
        pem.append("-----BEGIN CERTIFICATE-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            final int end = Math.min(i + 64, base64.length());
            pem.append(base64, i, end).append('\n');
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
            final byte[] pkcs12Data,
            final String keystorePassword,
            final String keyPassword,
            final String keyAlias)
            throws KeyStoreException,
                    NoSuchAlgorithmException,
                    CertificateException,
                    UnrecoverableKeyException,
                    OperatorCreationException,
                    org.bouncycastle.tsp.TSPException,
                    IOException {
        try {
            logGenerateNewCertificate("Updating signing key with new PKCS12 keystore");

            // Load the new PKCS12 keystore
            final KeyStore newKeystore = KeyStore.getInstance("PKCS12");
            try (java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(pkcs12Data)) {
                newKeystore.load(bais, keystorePassword.toCharArray());
            }

            // Determine key alias to use
            String effectiveKeyAlias = keyAlias;
            if (!StringUtils.hasText(effectiveKeyAlias)) {
                // Try to find the first private key entry
                final Enumeration<String> aliases = newKeystore.aliases();
                while (aliases.hasMoreElements() && effectiveKeyAlias == null) {
                    final String alias = aliases.nextElement();
                    if (newKeystore.isKeyEntry(alias)) {
                        effectiveKeyAlias = alias;
                    }
                }

                if (effectiveKeyAlias == null) {
                    throw new IllegalArgumentException("No private key found in the PKCS12 file");
                }
            }

            // Get private key
            final String keyPwd = StringUtils.hasText(keyPassword) ? keyPassword : keystorePassword;
            final PrivateKey newPrivateKey =
                    (PrivateKey) newKeystore.getKey(effectiveKeyAlias, keyPwd.toCharArray());
            if (newPrivateKey == null) {
                throw new IllegalArgumentException(
                        "Private key not found with alias: " + effectiveKeyAlias);
            }

            // Get certificate
            final Certificate newCert = newKeystore.getCertificate(effectiveKeyAlias);
            if (newCert == null) {
                throw new IllegalArgumentException(
                        "Certificate not found with alias: " + effectiveKeyAlias);
            }

            // Convert X509Certificate to X509CertificateHolder
            final X509Certificate x509Cert = (X509Certificate) newCert;
            final X509CertificateHolder newCertHolder =
                    new X509CertificateHolder(x509Cert.getEncoded());

            logCertInfo("Successfully loaded new key and certificate from PKCS12", x509Cert);

            // Update the TimeStampResponseGenerator with the new key and certificate
            final ContentSigner newContentSigner =
                    new JcaContentSignerBuilder(config.getSignatureAlgorithm())
                            .build(newPrivateKey);

            final DigestCalculatorProvider digestProvider =
                    new JcaDigestCalculatorProviderBuilder().build();
            final SignerInfoGenerator signerInfoGen =
                    new JcaSignerInfoGeneratorBuilder(digestProvider)
                            .build(newContentSigner, newCertHolder);

            final DigestCalculator digestCalc =
                    digestProvider.get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

            final TimeStampTokenGenerator newTokenGenerator =
                    new TimeStampTokenGenerator(
                            signerInfoGen,
                            digestCalc,
                            new ASN1ObjectIdentifier(config.getPolicyId()));

            // Add certificates to store
            final List<X509CertificateHolder> certs = new ArrayList<>();
            certs.add(newCertHolder);
            final JcaCertStore certStore = new JcaCertStore(certs);
            newTokenGenerator.addCertificates(certStore);

            final Set<ASN1ObjectIdentifier> algos = new HashSet<>();
            algos.add(NISTObjectIdentifiers.id_sha256);
            algos.add(NISTObjectIdentifiers.id_sha512);
            algos.add(OIWObjectIdentifiers.idSHA1);

            final Set<String> algoOids =
                    algos.stream().map(ASN1ObjectIdentifier::getId).collect(Collectors.toSet());

            final Set<String> policies = new HashSet<>();
            policies.add(config.getPolicyId());

            responseGen = new TimeStampResponseGenerator(newTokenGenerator, algoOids, policies);
            signCert = newCertHolder;

            logGenerateNewCertificate(
                    "Successfully updated TimeStampResponseGenerator with new signing key");
        } catch (IllegalArgumentException e) {
            if (LOGGER.isWarnEnabled()) {
                LOGGER.warn("Invalid input for key update: {}", e.getMessage());
            }
            throw e; // Re-throw for ControllerAdvice to handle
        } catch (KeyStoreException
                | NoSuchAlgorithmException
                | CertificateException
                | UnrecoverableKeyException
                | OperatorCreationException
                | org.bouncycastle.tsp.TSPException
                | IOException e) {
            if (LOGGER.isErrorEnabled()) {
                LOGGER.error("Failed to update signing key: {}", e.getMessage());
            }
            throw new IllegalStateException("Failed to update signing key: " + e.getMessage(), e);
        }
    }
}
