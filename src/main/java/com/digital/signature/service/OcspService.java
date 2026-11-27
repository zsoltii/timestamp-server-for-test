package com.digital.signature.service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/** In-memory OCSP test responder. All mutable state is protected by this instance's monitor. */
@Service
public class OcspService {
    private static final Logger LOGGER = LoggerFactory.getLogger(OcspService.class);
    private static final BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();
    private static final String OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";
    private static final String STATUS_GOOD = "GOOD";
    private static final String STATUS_REVOKED = "REVOKED";
    private static final String STATUS_UNKNOWN = "UNKNOWN";
    private static final int MAX_REQUEST_SIZE = 65_536;
    private static final int SUPPORTED_VERSION = 1;
    private static final CertificateStatus UNKNOWN_STATUS = new UnknownStatus();
    private static final java.util.regex.Pattern CUSTOM_PATH =
            java.util.regex.Pattern.compile("/[A-Za-z0-9._~/-]{1,200}");
    private static final java.util.regex.Pattern RESERVED_PATH =
            java.util.regex.Pattern.compile("^/(api|actuator|index\\.html|error)(/|$)");
    private final java.util.Set<String> customPathSet =
            new java.util.concurrent.CopyOnWriteArraySet<>();
    private final Map<String, Profile> profileMap = new LinkedHashMap<>();
    private Instant thisUpdate;
    private Instant nextUpdate;

    @SuppressWarnings("PMD.ShortVariable")
    public record ProfileInfo(String id, String issuer, String signer) {}

    public record Times(Instant thisUpdate, Instant nextUpdate) {}

    public record StatusEntry(
            String serialNumber, String status, Instant revocationTime, Integer reason) {}

    @SuppressWarnings("PMD.ShortVariable")
    private record Profile(
            String id,
            X509Certificate issuer,
            X509CertificateHolder issuerHolder,
            X509Certificate signer,
            PrivateKey key,
            Map<BigInteger, StatusEntry> statuses) {}

    /**
     * Adds or atomically replaces an issuer profile.
     *
     * @throws IllegalArgumentException if the key store or certificates are invalid
     */
    public synchronized void putProfile(
            final String profileId,
            final byte[] p12,
            final String password,
            final String keyPassword,
            final String alias,
            final byte[] issuerBytes) {
        requireId(profileId);
        if (p12 == null
                || p12.length == 0
                || issuerBytes == null
                || issuerBytes.length == 0
                || password == null) {
            throw new IllegalArgumentException(
                    "PKCS12, password and issuer certificate are required");
        }
        try {
            final KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(new ByteArrayInputStream(p12), password.toCharArray());
            final String selected = selectAlias(store, alias);
            final Key key =
                    store.getKey(
                            selected,
                            (keyPassword == null || keyPassword.isEmpty() ? password : keyPassword)
                                    .toCharArray());
            final Certificate certificate = store.getCertificate(selected);
            if (!(key instanceof PrivateKey privateKey)
                    || !(certificate instanceof X509Certificate signer)) {
                throw new IllegalArgumentException(
                        "An X.509 certificate and private key are required");
            }
            final X509Certificate issuer = parseSingleIssuer(issuerBytes);
            final IssuerIdentity identity = validateIssuerAndSigner(issuer, signer, privateKey);
            ensureUniqueIssuer(profileId, identity);
            final Profile previous = profileMap.get(profileId);
            final boolean sameCa =
                    previous != null && issuerIdentity(previous.issuer()).equals(identity);
            final Map<BigInteger, StatusEntry> statuses =
                    sameCa ? previous.statuses() : new LinkedHashMap<>();
            profileMap.put(
                    profileId,
                    new Profile(
                            profileId,
                            issuer,
                            new JcaX509CertificateHolder(issuer),
                            signer,
                            privateKey,
                            statuses));
            logProfileStored(profileId, previous, sameCa, issuer, signer);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid OCSP profile: " + e.getMessage(), e);
        }
    }

    private static void logProfileStored(
            final String profileId,
            final Profile previous,
            final boolean sameCa,
            final X509Certificate issuer,
            final X509Certificate signer) {
        if (LOGGER.isInfoEnabled()) {
            final String statusNote;
            if (previous == null) {
                statusNote = "new profile";
            } else if (sameCa) {
                statusNote =
                        "same CA, " + previous.statuses().size() + " configured status(es) kept";
            } else {
                statusNote =
                        "different CA, "
                                + previous.statuses().size()
                                + " configured status(es) cleared";
            }
            LOGGER.info(
                    "OCSP profile '{}' stored ({}): issuer {}, signer {} ({}), signer valid {} to"
                            + " {}",
                    profileId,
                    statusNote,
                    issuer.getSubjectX500Principal().getName(),
                    signer.getSubjectX500Principal().getName(),
                    signer.equals(issuer) ? "issuer signs directly" : "delegated OCSP signer",
                    signer.getNotBefore().toInstant(),
                    signer.getNotAfter().toInstant());
        }
    }

    private static String selectAlias(final KeyStore store, final String alias) throws Exception {
        String selected = alias;
        if (selected == null || selected.isBlank()) {
            final Enumeration<String> aliases = store.aliases();
            while (aliases.hasMoreElements()) {
                final String candidate = aliases.nextElement();
                if (store.isKeyEntry(candidate)) {
                    if (selected != null) {
                        throw new IllegalArgumentException("Multiple keys found; specify an alias");
                    }
                    selected = candidate;
                }
            }
        }
        if (selected == null || !store.isKeyEntry(selected)) {
            throw new IllegalArgumentException("Private key alias not found");
        }
        return selected;
    }

    private static X509Certificate parseSingleIssuer(final byte[] issuerBytes) throws Exception {
        final Collection<? extends Certificate> issuers =
                CertificateFactory.getInstance("X.509")
                        .generateCertificates(new ByteArrayInputStream(issuerBytes));
        if (issuers.size() != 1 || !(issuers.iterator().next() instanceof X509Certificate issuer)) {
            throw new IllegalArgumentException("Exactly one issuer certificate is required");
        }
        return issuer;
    }

    private static IssuerIdentity validateIssuerAndSigner(
            final X509Certificate issuer, final X509Certificate signer, final PrivateKey privateKey)
            throws Exception {
        if (issuer.getBasicConstraints() < 0) {
            throw new IllegalArgumentException("Issuer certificate must be a CA");
        }
        final boolean[] issuerUsage = issuer.getKeyUsage();
        if (issuerUsage != null && (issuerUsage.length <= 5 || !issuerUsage[5])) {
            throw new IllegalArgumentException("Issuer certificate cannot sign certificates");
        }
        final IssuerIdentity identity = issuerIdentity(issuer);
        if (!signer.equals(issuer)) {
            if (issuerIdentity(signer).equals(identity)) {
                throw new IllegalArgumentException(
                        "PKCS12 certificate does not match the uploaded issuer certificate");
            }
            if (!signer.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())
                    || signer.getExtendedKeyUsage() == null
                    || !signer.getExtendedKeyUsage().contains(OCSP_SIGNING)) {
                throw new IllegalArgumentException(
                        "Signer is not delegated for OCSP by this issuer");
            }
            final boolean[] usage = signer.getKeyUsage();
            if (usage != null && (usage.length == 0 || !usage[0])) {
                throw new IllegalArgumentException(
                        "Signer certificate does not permit digital signatures");
            }
            signer.verify(issuer.getPublicKey());
        }
        verifyKeyMatchesCertificate(privateKey, signer);
        return identity;
    }

    private static void verifyKeyMatchesCertificate(
            final PrivateKey privateKey, final X509Certificate signer) throws Exception {
        final byte[] challenge = "OCSP key validation".getBytes(StandardCharsets.US_ASCII);
        final ContentSigner contentSigner =
                SigningAlgorithm.auto(privateKey, "OCSP").build(privateKey);
        contentSigner.getOutputStream().write(challenge);
        final ContentVerifier verifier =
                new JcaContentVerifierProviderBuilder()
                        .setProvider(BC_PROVIDER)
                        .build(signer.getPublicKey())
                        .get(contentSigner.getAlgorithmIdentifier());
        verifier.getOutputStream().write(challenge);
        if (!verifier.verify(contentSigner.getSignature())) {
            throw new IllegalArgumentException("Private key does not match signer certificate");
        }
    }

    private void ensureUniqueIssuer(final String profileId, final IssuerIdentity identity) {
        for (final Map.Entry<String, Profile> entry : profileMap.entrySet()) {
            if (!entry.getKey().equals(profileId)
                    && issuerIdentity(entry.getValue().issuer()).equals(identity)) {
                throw new IllegalArgumentException(
                        "Issuer already has a profile: " + entry.getKey());
            }
        }
    }

    /**
     * OCSP issuer identity as matched by a CertID: the DER encoded subject name and the subject
     * public key bits. Renewed certificates with the same name and key share one identity.
     */
    /* default */ record IssuerIdentity(String subject, String publicKey) {}

    /**
     * Computes the OCSP issuer identity of a certificate.
     *
     * @throws IllegalArgumentException if the certificate is null or cannot be encoded
     */
    /* default */ static IssuerIdentity issuerIdentity(final X509Certificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("Issuer certificate is required");
        }
        try {
            final X509CertificateHolder holder = new JcaX509CertificateHolder(certificate);
            final HexFormat hex = HexFormat.of();
            return new IssuerIdentity(
                    hex.formatHex(holder.getSubject().getEncoded(ASN1Encoding.DER)),
                    hex.formatHex(holder.getSubjectPublicKeyInfo().getPublicKeyData().getBytes()));
        } catch (CertificateEncodingException | IOException e) {
            throw new IllegalArgumentException("Cannot encode issuer certificate", e);
        }
    }

    private static void requireId(final String profileId) {
        if (profileId == null || !profileId.matches("[A-Za-z0-9_-]{1,64}")) {
            throw new IllegalArgumentException(
                    "Profile id must contain 1-64 letters, digits, underscores or hyphens");
        }
    }

    /** Lists profiles without exposing private keys. */
    public synchronized List<ProfileInfo> profiles() {
        return profileMap.entrySet().stream()
                .map(
                        e ->
                                new ProfileInfo(
                                        e.getKey(),
                                        e.getValue().issuer().getSubjectX500Principal().getName(),
                                        e.getValue().signer().getSubjectX500Principal().getName()))
                .toList();
    }

    /** Deletes a profile and its statuses. */
    public synchronized void deleteProfile(final String profileId) {
        profile(profileId);
        profileMap.remove(profileId);
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("OCSP profile '{}' deleted", profileId);
        }
    }

    private Profile profile(final String profileId) {
        requireId(profileId);
        final Profile result = profileMap.get(profileId);
        if (result == null) {
            throw new IllegalArgumentException("Unknown OCSP profile: " + profileId);
        }
        return result;
    }

    /** Sets the test status for a hexadecimal certificate serial number. */
    public synchronized void putStatus(
            final String profileId, final String serial, final StatusEntry entry) {
        final BigInteger number = serial(serial);
        if (entry == null
                || entry.status() == null
                || !List.of(STATUS_GOOD, STATUS_REVOKED, STATUS_UNKNOWN).contains(entry.status())) {
            throw new IllegalArgumentException("Status must be GOOD, REVOKED or UNKNOWN");
        }
        if (STATUS_REVOKED.equals(entry.status())) {
            if (entry.revocationTime() == null
                    || (entry.reason() != null
                            && (entry.reason() < 0
                                    || entry.reason() > 10
                                    || entry.reason() == 7))) {
                throw new IllegalArgumentException(
                        "REVOKED requires a revocation time and valid reason");
            }
        } else if (entry.revocationTime() != null || entry.reason() != null) {
            throw new IllegalArgumentException("Revocation details are only valid for REVOKED");
        }
        final StatusEntry stored =
                new StatusEntry(
                        number.toString(16).toUpperCase(Locale.ROOT),
                        entry.status(),
                        entry.revocationTime(),
                        entry.reason());
        profile(profileId).statuses().put(number, stored);
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info(
                    "OCSP status of serial {} in profile '{}' set to {}",
                    stored.serialNumber(),
                    profileId,
                    describeStatus(stored));
        }
        if (isRevocationAfterStart(stored, thisUpdate) && LOGGER.isWarnEnabled()) {
            LOGGER.warn(
                    "OCSP serial {} in profile '{}' is revoked at {}, after the simulated"
                            + " thisUpdate {}; requests for it will get internalError",
                    stored.serialNumber(),
                    profileId,
                    stored.revocationTime(),
                    thisUpdate);
        }
    }

    private static BigInteger serial(final String value) {
        if (value == null || !value.matches("[0-9a-fA-F]{1,40}")) {
            throw new IllegalArgumentException("Serial number must be 1-40 hexadecimal digits");
        }
        return new BigInteger(value, 16);
    }

    /** Lists statuses for an issuer. */
    public synchronized List<StatusEntry> statuses(final String profileId) {
        return List.copyOf(profile(profileId).statuses().values());
    }

    /** Removes a status, returning the certificate to the default GOOD status. */
    public synchronized void deleteStatus(final String profileId, final String serial) {
        if (profile(profileId).statuses().remove(serial(serial)) == null) {
            throw new IllegalArgumentException(
                    "Certificate status not found: serial " + serial + " in profile " + profileId);
        }
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info(
                    "OCSP status of serial {} in profile '{}' removed (GOOD by default)",
                    serial,
                    profileId);
        }
    }

    /** Replaces both optional fixed time settings atomically. */
    public synchronized void setTimes(final Times times) {
        if (times == null) {
            throw new IllegalArgumentException("Time settings are required");
        }
        if (times.thisUpdate() == null && times.nextUpdate() != null) {
            throw new IllegalArgumentException("A fixed nextUpdate requires a fixed thisUpdate");
        }
        if (times.nextUpdate() != null && times.nextUpdate().isBefore(times.thisUpdate())) {
            throw new IllegalArgumentException("nextUpdate cannot precede thisUpdate");
        }
        thisUpdate = times.thisUpdate();
        nextUpdate = times.nextUpdate();
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info(
                    "OCSP times set: thisUpdate={}, nextUpdate={}",
                    thisUpdate == null ? "current time" : thisUpdate,
                    nextUpdate == null ? "thisUpdate + 24 hours" : nextUpdate);
        }
    }

    /** Returns the configured fixed time settings. */
    public synchronized Times times() {
        return new Times(thisUpdate, nextUpdate);
    }

    /**
     * Registers an additional URL path that is served by the OCSP responder.
     *
     * @param path absolute path such as {@code /ca/ocsp}; a trailing slash is ignored
     * @return the normalized path
     * @throws IllegalArgumentException if the path is blank, malformed or reserved
     */
    public String addCustomPath(final String path) {
        final String normalized = normalizeCustomPath(path);
        if (customPathSet.add(normalized) && LOGGER.isInfoEnabled()) {
            LOGGER.info("OCSP responder also serves custom path {}", normalized);
        }
        return normalized;
    }

    /** Removes a custom path; returns whether it was registered. */
    public boolean removeCustomPath(final String path) {
        final boolean removed =
                path != null && customPathSet.remove(stripTrailingSlash(path.trim()));
        if (removed && LOGGER.isInfoEnabled()) {
            LOGGER.info("OCSP custom path {} removed", stripTrailingSlash(path.trim()));
        }
        return removed;
    }

    /** Returns the registered custom paths in registration order. */
    public List<String> customPaths() {
        return List.copyOf(customPathSet);
    }

    /**
     * Matches a request path against the custom paths.
     *
     * @return the (still encoded) text after the custom path, empty for an exact match, or {@code
     *     null} when no custom path matches
     */
    public String customPathRemainder(final String requestPath) {
        String remainder = null;
        int matchedLength = -1;
        if (requestPath != null) {
            for (final String custom : customPathSet) {
                if (custom.length() > matchedLength) {
                    final String candidate = remainderAfter(requestPath, custom);
                    if (candidate != null) {
                        remainder = candidate;
                        matchedLength = custom.length();
                    }
                }
            }
        }
        return remainder;
    }

    private static String remainderAfter(final String requestPath, final String custom) {
        String remainder = null;
        if (requestPath.equals(custom) || requestPath.equals(custom + "/")) {
            remainder = "";
        } else if (requestPath.startsWith(custom + "/")) {
            remainder = requestPath.substring(custom.length() + 1);
        }
        return remainder;
    }

    private static String stripTrailingSlash(final String path) {
        String result = path;
        while (result.length() > 1 && result.endsWith("/")) {
            result = result.substring(0, result.length() - 1);
        }
        return result;
    }

    private static String normalizeCustomPath(final String path) {
        if (path == null || path.isBlank()) {
            throw new IllegalArgumentException("OCSP path is required");
        }
        final String normalized = stripTrailingSlash(path.trim());
        if (!CUSTOM_PATH.matcher(normalized).matches() || normalized.contains("//")) {
            throw new IllegalArgumentException(
                    "OCSP path must start with '/' and contain only letters, digits and"
                            + " '/', '.', '_', '-', '~'");
        }
        if ("/".equals(normalized)
                || normalized.contains("/./")
                || normalized.contains("/../")
                || RESERVED_PATH.matcher(normalized).find()) {
            throw new IllegalArgumentException(
                    "OCSP path is reserved or too general: " + normalized);
        }
        return normalized;
    }

    /**
     * Generates a DER OCSP response; malformed and unauthorized requests receive protocol errors.
     * Every non-successful answer is logged at WARN with its reason; successful answers at INFO.
     */
    public synchronized byte[] respond(final byte[] requestBytes) {
        final RequestCheck check = parseAndValidateRequest(requestBytes);
        final byte[] response;
        if (check.request() == null) {
            logMalformed(check.reason());
            response = error(OCSPRespBuilder.MALFORMED_REQUEST);
        } else {
            response = buildResponse(check.request());
        }
        return response;
    }

    private record RequestCheck(OCSPReq request, String reason) {}

    private static RequestCheck parseAndValidateRequest(final byte[] requestBytes) {
        final RequestCheck check;
        if (requestBytes == null || requestBytes.length == 0) {
            check =
                    new RequestCheck(
                            null, "the request is empty (no POST body or undecodable GET request)");
        } else if (requestBytes.length > MAX_REQUEST_SIZE) {
            check =
                    new RequestCheck(
                            null,
                            "the request is too large: "
                                    + requestBytes.length
                                    + " bytes (max "
                                    + MAX_REQUEST_SIZE
                                    + ")");
        } else {
            check = parseDer(requestBytes);
        }
        return check;
    }

    private static RequestCheck parseDer(final byte[] requestBytes) {
        RequestCheck check;
        try {
            final OCSPReq candidate = new OCSPReq(requestBytes);
            final String reason = malformedReason(candidate, requestBytes);
            check = new RequestCheck(reason == null ? candidate : null, reason);
        } catch (IOException | RuntimeException e) {
            check =
                    new RequestCheck(
                            null, "the body is not a DER encoded OCSPRequest: " + e.getMessage());
        }
        return check;
    }

    private static String malformedReason(final OCSPReq request, final byte[] requestBytes)
            throws IOException {
        String reason = null;
        if (request.getRequestList().length == 0) {
            reason = "the request list is empty";
        }
        if (request.getVersionNumber() != SUPPORTED_VERSION) {
            reason = "unsupported request version v" + request.getVersionNumber();
        }
        if (!Arrays.equals(request.getEncoded(), requestBytes)) {
            reason = "the request is not DER encoded (BER encoding or trailing bytes)";
        }
        if (reason == null) {
            reason = extensionReason(request);
        }
        return reason;
    }

    private static String extensionReason(final OCSPReq request) {
        String reason = null;
        for (final Object oid : request.getCriticalExtensionOIDs()) {
            if (!OCSPObjectIdentifiers.id_pkix_ocsp_nonce.equals(oid)) {
                reason = "unsupported critical request extension " + oid;
            }
        }
        final Extension nonce = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (reason == null && nonce != null) {
            final int length =
                    ASN1OctetString.getInstance(nonce.getParsedValue()).getOctets().length;
            if (length < 1 || length > 32) {
                reason = "the nonce is " + length + " bytes long (allowed: 1-32)";
            }
        }
        for (final Req req : request.getRequestList()) {
            if (reason == null
                    && req.getSingleRequestExtensions() != null
                    && req.getSingleRequestExtensions().getCriticalExtensionOIDs().length != 0) {
                reason =
                        "unsupported critical single request extension for serial "
                                + OcspDiagnostics.serialHex(req.getCertID().getSerialNumber());
            }
        }
        return reason;
    }

    private static void logMalformed(final String reason) {
        if (LOGGER.isWarnEnabled()) {
            LOGGER.warn("OCSP response malformedRequest: {}", reason);
        }
    }

    private byte[] buildResponse(final OCSPReq request) {
        byte[] responseBytes;
        try {
            final DigestCalculatorProvider digests =
                    new JcaDigestCalculatorProviderBuilder().build();
            logRequest(request);
            final String unsupportedHash = unsupportedHashReason(request);
            if (unsupportedHash == null) {
                final Optional<Profile> selected = selectProfile(request, digests);
                responseBytes =
                        selected.isEmpty()
                                ? error(OCSPRespBuilder.UNAUTHORIZED)
                                : signResponse(request, selected.get(), digests);
            } else {
                logMalformed(unsupportedHash);
                responseBytes = error(OCSPRespBuilder.MALFORMED_REQUEST);
            }
        } catch (Exception e) {
            if (LOGGER.isErrorEnabled()) {
                LOGGER.error("OCSP response internalError: cannot generate the response", e);
            }
            responseBytes = error(OCSPRespBuilder.INTERNAL_ERROR);
        }
        return responseBytes;
    }

    private static void logRequest(final OCSPReq request) {
        if (LOGGER.isDebugEnabled()) {
            final List<String> ids = new ArrayList<>();
            for (final Req req : request.getRequestList()) {
                ids.add(OcspDiagnostics.describe(req.getCertID()));
            }
            LOGGER.debug(
                    "OCSP request: {} certificate(s) {}, nonce={}",
                    ids.size(),
                    ids,
                    request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce) != null);
        }
    }

    private static String unsupportedHashReason(final OCSPReq request) {
        String reason = null;
        for (final Req req : request.getRequestList()) {
            final ASN1ObjectIdentifier hash = req.getCertID().getHashAlgOID();
            if (reason == null
                    && !hash.equals(OIWObjectIdentifiers.idSHA1)
                    && !hash.equals(NISTObjectIdentifiers.id_sha256)
                    && !hash.equals(NISTObjectIdentifiers.id_sha512)) {
                reason =
                        "unsupported CertID hash algorithm "
                                + hash.getId()
                                + " (supported: SHA-1, SHA-256, SHA-512)";
            }
        }
        return reason;
    }

    private Optional<Profile> selectProfile(
            final OCSPReq request, final DigestCalculatorProvider digests) throws OCSPException {
        Optional<Profile> selected = Optional.empty();
        String problem = null;
        for (final Req req : request.getRequestList()) {
            final CertificateID certId = req.getCertID();
            final Optional<Profile> match = findMatchingProfile(certId, digests);
            if (match.isEmpty()) {
                problem = noProfileReason(certId, digests);
                break;
            }
            if (selected.isPresent() && !selected.get().id().equals(match.get().id())) {
                problem =
                        "the request mixes issuers: profile '"
                                + selected.get().id()
                                + "' and profile '"
                                + match.get().id()
                                + "' (serial "
                                + OcspDiagnostics.serialHex(certId.getSerialNumber())
                                + "); send a separate request per CA";
                break;
            }
            selected = match;
        }
        if (problem != null) {
            if (LOGGER.isWarnEnabled()) {
                LOGGER.warn("OCSP response unauthorized: {}", problem);
            }
            selected = Optional.empty();
        }
        return selected;
    }

    private String noProfileReason(
            final CertificateID certId, final DigestCalculatorProvider digests) {
        final StringBuilder reason =
                new StringBuilder(256)
                        .append("no issuer profile matches ")
                        .append(OcspDiagnostics.describe(certId));
        if (profileMap.isEmpty()) {
            reason.append("; no OCSP issuer profile is configured");
        }
        for (final Profile profile : profileMap.values()) {
            reason.append("; ")
                    .append(
                            OcspDiagnostics.compare(
                                    profile.id(), profile.issuerHolder(), certId, digests));
        }
        return reason.toString();
    }

    private Optional<Profile> findMatchingProfile(
            final CertificateID certId, final DigestCalculatorProvider digests)
            throws OCSPException {
        Optional<Profile> match = Optional.empty();
        for (final Profile candidate : profileMap.values()) {
            if (certId.matchesIssuer(candidate.issuerHolder(), digests)) {
                if (match.isPresent()) {
                    match = Optional.empty();
                    break;
                }
                match = Optional.of(candidate);
            }
        }
        return match;
    }

    private byte[] signResponse(
            final OCSPReq request, final Profile selected, final DigestCalculatorProvider digests)
            throws Exception {
        final Instant start = thisUpdate == null ? Instant.now() : thisUpdate;
        final Instant end = nextUpdate == null ? start.plus(1, ChronoUnit.DAYS) : nextUpdate;
        String problem = OcspDiagnostics.validityProblem("signer", selected.signer(), start);
        if (problem == null) {
            problem = OcspDiagnostics.validityProblem("issuer", selected.issuer(), start);
        }
        if (problem == null) {
            problem = revocationProblem(request, selected, start);
        }
        final byte[] encoded;
        if (problem == null) {
            encoded = buildSignedResponse(request, selected, digests, start, end);
            logSuccess(request, selected, start, end);
        } else {
            if (LOGGER.isWarnEnabled()) {
                LOGGER.warn(
                        "OCSP response internalError for profile '{}': {}", selected.id(), problem);
            }
            encoded = error(OCSPRespBuilder.INTERNAL_ERROR);
        }
        return encoded;
    }

    private static String revocationProblem(
            final OCSPReq request, final Profile selected, final Instant start) {
        String problem = null;
        for (final Req req : request.getRequestList()) {
            final StatusEntry entry = selected.statuses().get(req.getCertID().getSerialNumber());
            if (problem == null && isRevocationAfterStart(entry, start)) {
                problem =
                        "serial "
                                + entry.serialNumber()
                                + " is revoked at "
                                + entry.revocationTime()
                                + ", after thisUpdate "
                                + start
                                + "; set an earlier revocationTime or a later simulated time";
            }
        }
        return problem;
    }

    private static byte[] buildSignedResponse(
            final OCSPReq request,
            final Profile selected,
            final DigestCalculatorProvider digests,
            final Instant start,
            final Instant end)
            throws Exception {
        final BasicOCSPRespBuilder builder =
                new JcaBasicOCSPRespBuilder(
                        selected.signer().getPublicKey(), digests.get(CertificateID.HASH_SHA1));
        for (final Req req : request.getRequestList()) {
            builder.addResponse(
                    req.getCertID(),
                    resolveCertificateStatus(
                            selected.statuses().get(req.getCertID().getSerialNumber())),
                    Date.from(start),
                    Date.from(end));
        }
        final Extension nonce = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (nonce != null) {
            builder.setResponseExtensions(new Extensions(new Extension[] {nonce}));
        }
        return new OCSPRespBuilder()
                .build(
                        OCSPRespBuilder.SUCCESSFUL,
                        builder.build(
                                SigningAlgorithm.auto(selected.key(), "OCSP").build(selected.key()),
                                buildCertificateChain(selected),
                                Date.from(start)))
                .getEncoded();
    }

    private static void logSuccess(
            final OCSPReq request, final Profile selected, final Instant start, final Instant end) {
        if (LOGGER.isInfoEnabled()) {
            final List<String> statuses = new ArrayList<>();
            for (final Req req : request.getRequestList()) {
                final BigInteger serial = req.getCertID().getSerialNumber();
                statuses.add(
                        OcspDiagnostics.serialHex(serial)
                                + "="
                                + describeStatus(selected.statuses().get(serial)));
            }
            LOGGER.info(
                    "OCSP response successful: profile '{}', signer {}, thisUpdate={},"
                            + " nextUpdate={}, statuses {}",
                    selected.id(),
                    selected.signer().getSubjectX500Principal().getName(),
                    start,
                    end,
                    statuses);
        }
    }

    private static String describeStatus(final StatusEntry entry) {
        String text = "GOOD (default)";
        if (entry != null && STATUS_REVOKED.equals(entry.status())) {
            text =
                    "REVOKED at "
                            + entry.revocationTime()
                            + (entry.reason() == null ? "" : " reason " + entry.reason());
        } else if (entry != null) {
            text = entry.status();
        }
        return text;
    }

    private static boolean isRevocationAfterStart(final StatusEntry entry, final Instant start) {
        return entry != null
                && start != null
                && STATUS_REVOKED.equals(entry.status())
                && entry.revocationTime().isAfter(start);
    }

    private static CertificateStatus resolveCertificateStatus(final StatusEntry entry) {
        CertificateStatus status = CertificateStatus.GOOD;
        if (entry != null && STATUS_REVOKED.equals(entry.status())) {
            status = createRevokedStatus(entry);
        } else if (entry != null && STATUS_UNKNOWN.equals(entry.status())) {
            status = UNKNOWN_STATUS;
        }
        return status;
    }

    private static RevokedStatus createRevokedStatus(final StatusEntry entry) {
        return entry.reason() == null
                ? new RevokedStatus(Date.from(entry.revocationTime()))
                : new RevokedStatus(Date.from(entry.revocationTime()), entry.reason());
    }

    private static X509CertificateHolder[] buildCertificateChain(final Profile selected)
            throws CertificateEncodingException {
        final List<X509CertificateHolder> chain = new ArrayList<>();
        chain.add(new JcaX509CertificateHolder(selected.signer()));
        if (!selected.signer().equals(selected.issuer())) {
            chain.add(selected.issuerHolder());
        }
        return chain.toArray(X509CertificateHolder[]::new);
    }

    private static byte[] error(final int status) {
        try {
            return new OCSPRespBuilder().build(status, null).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Cannot encode OCSP error response", e);
        }
    }
}
