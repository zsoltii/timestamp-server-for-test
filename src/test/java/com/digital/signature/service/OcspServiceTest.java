package com.digital.signature.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class OcspServiceTest {
    private static final Instant SIMULATED = Instant.parse("2029-01-01T00:00:00Z");
    private OcspService service;
    private Fixture fixture;

    record Fixture(X509Certificate issuer, X509Certificate signer, byte[] store) {}

    @BeforeEach
    void setUp() throws Exception {
        service = new OcspService();
        fixture = fixture("RSA", true);
        service.putProfile(
                "issuer", fixture.store(), "password", null, null, fixture.issuer().getEncoded());
    }

    private static Fixture fixture(String algorithm, boolean delegated) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        if (algorithm.equals("EC")) {
            generator.initialize(256);
        } else if (algorithm.equals("RSA")
                || algorithm.equals("RSASSA-PSS")
                || algorithm.equals("DSA")) {
            generator.initialize(2048);
        }
        KeyPair ca = generator.generateKeyPair();
        KeyPair signer = delegated ? generator.generateKeyPair() : ca;
        String signatureAlgorithm =
                switch (algorithm) {
                    case "EC" -> "SHA256withECDSA";
                    case "RSASSA-PSS" -> "SHA256withRSAandMGF1";
                    case "DSA" -> "SHA256withDSA";
                    case "Ed25519" -> "Ed25519";
                    case "Ed448" -> "Ed448";
                    case "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" -> algorithm;
                    default -> "SHA256withRSA";
                };
        JcaContentSignerBuilder caSigner = new JcaContentSignerBuilder(signatureAlgorithm);
        if (algorithm.equals("RSASSA-PSS")) {
            caSigner.setProvider(new BouncyCastleProvider());
        }
        X500Name caName = new X500Name("CN=Test CA " + algorithm);
        Date from = Date.from(Instant.parse("2025-01-01T00:00:00Z"));
        Date until = Date.from(Instant.parse("2030-01-01T00:00:00Z"));
        JcaX509v3CertificateBuilder caBuilder =
                new JcaX509v3CertificateBuilder(
                        caName, BigInteger.ONE, from, until, caName, ca.getPublic());
        caBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        caBuilder.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature));
        X509Certificate issuer =
                new JcaX509CertificateConverter()
                        .getCertificate(caBuilder.build(caSigner.build(ca.getPrivate())));
        X509Certificate signingCert = issuer;
        if (delegated) {
            JcaX509v3CertificateBuilder builder =
                    new JcaX509v3CertificateBuilder(
                            caName,
                            BigInteger.TWO,
                            from,
                            until,
                            new X500Name("CN=OCSP"),
                            signer.getPublic());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            builder.addExtension(
                    Extension.extendedKeyUsage,
                    false,
                    new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
            signingCert =
                    new JcaX509CertificateConverter()
                            .getCertificate(builder.build(caSigner.build(ca.getPrivate())));
        }
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setKeyEntry(
                "ocsp",
                signer.getPrivate(),
                "password".toCharArray(),
                delegated ? new Certificate[] {signingCert, issuer} : new Certificate[] {issuer});
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        store.store(output, "password".toCharArray());
        return new Fixture(issuer, signingCert, output.toByteArray());
    }

    private static CertificateID id(X509Certificate issuer, int serial) throws Exception {
        return new CertificateID(
                new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                new JcaX509CertificateHolder(issuer),
                BigInteger.valueOf(serial));
    }

    private static byte[] request(CertificateID... ids) throws Exception {
        OCSPReqBuilder builder = new OCSPReqBuilder();
        for (CertificateID id : ids) builder.addRequest(id);
        builder.setRequestExtensions(
                new Extensions(
                        new Extension(
                                OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                                false,
                                new DEROctetString(new byte[] {1, 2, 3}).getEncoded())));
        return builder.build().getEncoded();
    }

    @Test
    void signsMultipleStatusesAndEchoesNonceAtSimulatedTime() throws Exception {
        service.setTimes(new OcspService.Times(SIMULATED, SIMULATED.plusSeconds(60)));
        service.putStatus("issuer", "10", new OcspService.StatusEntry(null, "GOOD", null, null));
        service.putStatus(
                "issuer",
                "11",
                new OcspService.StatusEntry(null, "REVOKED", SIMULATED.minusSeconds(120), 1));
        byte[] input =
                request(
                        id(fixture.issuer(), 16),
                        id(fixture.issuer(), 17),
                        id(fixture.issuer(), 18));
        OCSPResp response = new OCSPResp(service.respond(input));
        assertThat(response.getStatus()).isEqualTo(OCSPRespBuilder.SUCCESSFUL);
        BasicOCSPResp basic = (BasicOCSPResp) response.getResponseObject();
        assertThat(
                        basic.isSignatureValid(
                                new JcaContentVerifierProviderBuilder()
                                        .build(fixture.signer().getPublicKey())))
                .isTrue();
        assertThat(basic.getProducedAt().toInstant()).isEqualTo(SIMULATED);
        assertThat(basic.getResponses()).hasSize(3);
        assertThat(basic.getResponses()[0].getCertStatus()).isNull();
        assertThat(basic.getResponses()[1].getCertStatus()).isInstanceOf(RevokedStatus.class);
        assertThat(basic.getResponses()[2].getCertStatus()).isNull();
        assertThat(basic.getResponses()[0].getThisUpdate().toInstant()).isEqualTo(SIMULATED);
        assertThat(basic.getResponses()[0].getNextUpdate().toInstant())
                .isEqualTo(SIMULATED.plusSeconds(60));
        assertThat(basic.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce))
                .isEqualTo(
                        new org.bouncycastle.cert.ocsp.OCSPReq(input)
                                .getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce));
        assertThat(basic.getCerts()).hasSize(2);
    }

    @Test
    void supportsSeparateIssuerAndEcSignerButRejectsMixedIssuers() throws Exception {
        Fixture ec = fixture("EC", false);
        service.putProfile("ec", ec.store(), "password", null, null, ec.issuer().getEncoded());
        service.setTimes(new OcspService.Times(SIMULATED, null));
        BasicOCSPResp basic =
                (BasicOCSPResp)
                        new OCSPResp(service.respond(request(id(ec.issuer(), 1))))
                                .getResponseObject();
        assertThat(
                        basic.isSignatureValid(
                                new JcaContentVerifierProviderBuilder()
                                        .build(ec.signer().getPublicKey())))
                .isTrue();
        assertThat(basic.getResponses()[0].getNextUpdate().toInstant())
                .isEqualTo(SIMULATED.plusSeconds(86400));
        assertThat(
                        new OCSPResp(
                                        service.respond(
                                                request(
                                                        id(ec.issuer(), 1),
                                                        id(fixture.issuer(), 2))))
                                .getStatus())
                .isEqualTo(OCSPRespBuilder.UNAUTHORIZED);
    }

    @Test
    void rejectsMalformedUnknownAndInvalidTimeRequests() throws Exception {
        assertThat(new OCSPResp(service.respond(null)).getStatus())
                .isEqualTo(OCSPRespBuilder.MALFORMED_REQUEST);
        assertThat(new OCSPResp(service.respond(new byte[] {1, 2})).getStatus())
                .isEqualTo(OCSPRespBuilder.MALFORMED_REQUEST);
        Fixture other = fixture("EC", true);
        assertThat(new OCSPResp(service.respond(request(id(other.issuer(), 1)))).getStatus())
                .isEqualTo(OCSPRespBuilder.UNAUTHORIZED);
        service.setTimes(new OcspService.Times(Instant.parse("2031-01-01T00:00:00Z"), null));
        assertThat(new OCSPResp(service.respond(request(id(fixture.issuer(), 1)))).getStatus())
                .isEqualTo(OCSPRespBuilder.INTERNAL_ERROR);
        service.setTimes(new OcspService.Times(SIMULATED, null));
        service.putStatus(
                "issuer",
                "1",
                new OcspService.StatusEntry(null, "REVOKED", SIMULATED.plusSeconds(1), null));
        assertThat(new OCSPResp(service.respond(request(id(fixture.issuer(), 1)))).getStatus())
                .isEqualTo(OCSPRespBuilder.INTERNAL_ERROR);
    }

    @Test
    void validatesSettingsAndKeepsExistingProfileOnFailure() throws Exception {
        assertThatThrownBy(
                        () ->
                                service.putProfile(
                                        "issuer",
                                        fixture.store(),
                                        "bad",
                                        null,
                                        null,
                                        fixture.issuer().getEncoded()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(service.profiles()).hasSize(1);
        assertThatThrownBy(() -> service.setTimes(new OcspService.Times(null, SIMULATED)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(
                        () ->
                                service.setTimes(
                                        new OcspService.Times(
                                                SIMULATED, SIMULATED.minusSeconds(1))))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(
                        () ->
                                service.putStatus(
                                        "issuer",
                                        "xx",
                                        new OcspService.StatusEntry(null, "GOOD", null, null)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(
                        () ->
                                service.putStatus(
                                        "issuer",
                                        "1",
                                        new OcspService.StatusEntry(null, "REVOKED", null, null)))
                .isInstanceOf(IllegalArgumentException.class);
        service.putStatus("issuer", "a", new OcspService.StatusEntry(null, "GOOD", null, null));
        assertThat(service.statuses("issuer")).hasSize(1);
        service.deleteStatus("issuer", "A");
        assertThat(service.statuses("issuer")).isEmpty();
        assertThatThrownBy(() -> service.deleteStatus("issuer", "A"))
                .isInstanceOf(IllegalArgumentException.class);
        service.deleteProfile("issuer");
        assertThat(service.profiles()).isEmpty();
        assertThatThrownBy(() -> service.deleteProfile("issuer"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsWrongIssuerDuplicateProfileAndInvalidStatuses() throws Exception {
        Fixture wrong = fixture("EC", false);
        assertThatThrownBy(
                        () ->
                                service.putProfile(
                                        "issuer",
                                        fixture.store(),
                                        "password",
                                        null,
                                        null,
                                        wrong.issuer().getEncoded()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(
                        () ->
                                service.putProfile(
                                        "duplicate",
                                        fixture.store(),
                                        "password",
                                        null,
                                        null,
                                        fixture.issuer().getEncoded()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(
                        () ->
                                service.putProfile(
                                        "",
                                        fixture.store(),
                                        "password",
                                        null,
                                        null,
                                        fixture.issuer().getEncoded()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(
                        () ->
                                service.putStatus(
                                        "issuer",
                                        "1",
                                        new OcspService.StatusEntry(null, "GOOD", SIMULATED, null)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(
                        () ->
                                service.putStatus(
                                        "issuer",
                                        "1",
                                        new OcspService.StatusEntry(null, "REVOKED", SIMULATED, 7)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(
                        () ->
                                service.putStatus(
                                        "issuer",
                                        "1",
                                        new OcspService.StatusEntry(null, "INVALID", null, null)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(service.profiles()).hasSize(1);
        assertThat(service.statuses("issuer")).isEmpty();
    }

    @Test
    void rejectsUnknownCriticalExtensionAndEchoesCriticalNonce() throws Exception {
        OCSPReqBuilder bad = new OCSPReqBuilder();
        bad.addRequest(id(fixture.issuer(), 1));
        bad.setRequestExtensions(
                new Extensions(
                        new Extension(
                                new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.3.4"),
                                true,
                                new DEROctetString(new byte[] {1}).getEncoded())));
        assertThat(new OCSPResp(service.respond(bad.build().getEncoded())).getStatus())
                .isEqualTo(OCSPRespBuilder.MALFORMED_REQUEST);
        OCSPReqBuilder nonce = new OCSPReqBuilder();
        nonce.addRequest(id(fixture.issuer(), 1));
        nonce.setRequestExtensions(
                new Extensions(
                        new Extension(
                                OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                                true,
                                new DEROctetString(new byte[] {1, 2}).getEncoded())));
        service.setTimes(new OcspService.Times(Instant.parse("2027-01-01T00:00:00Z"), null));
        BasicOCSPResp basic =
                (BasicOCSPResp)
                        new OCSPResp(service.respond(nonce.build().getEncoded()))
                                .getResponseObject();
        assertThat(basic.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce)).isNotNull();
        OCSPReqBuilder oversized = new OCSPReqBuilder();
        oversized.addRequest(id(fixture.issuer(), 1));
        oversized.setRequestExtensions(
                new Extensions(
                        new Extension(
                                OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                                false,
                                new DEROctetString(new byte[33]).getEncoded())));
        assertThat(new OCSPResp(service.respond(oversized.build().getEncoded())).getStatus())
                .isEqualTo(OCSPRespBuilder.MALFORMED_REQUEST);
    }

    @ParameterizedTest
    @CsvSource({
        "RSA, SHA256withRSA",
        "RSASSA-PSS, SHA256withRSAandMGF1",
        "EC, SHA256withECDSA",
        "DSA, SHA256withDSA",
        "Ed25519, Ed25519",
        "Ed448, Ed448",
        "ML-DSA-44, ML-DSA-44",
        "ML-DSA-65, ML-DSA-65",
        "ML-DSA-87, ML-DSA-87"
    })
    void automaticallySignsWithUploadedKey(String keyAlgorithm, String expectedAlgorithm)
            throws Exception {
        Fixture signer = fixture(keyAlgorithm, true);
        service.putProfile(
                "auto", signer.store(), "password", null, null, signer.issuer().getEncoded());
        service.setTimes(new OcspService.Times(SIMULATED, null));
        OCSPResp response = new OCSPResp(service.respond(request(id(signer.issuer(), 1))));
        assertThat(response.getStatus()).isEqualTo(OCSPRespBuilder.SUCCESSFUL);
        BasicOCSPResp basic = (BasicOCSPResp) response.getResponseObject();
        assertThat(basic.getSignatureAlgOID())
                .isEqualTo(
                        new DefaultSignatureAlgorithmIdentifierFinder()
                                .find(expectedAlgorithm)
                                .getAlgorithm());
        assertThat(
                        basic.isSignatureValid(
                                new JcaContentVerifierProviderBuilder()
                                        .setProvider(new BouncyCastleProvider())
                                        .build(signer.signer().getPublicKey())))
                .isTrue();
    }

    @Test
    void unlistedSerialIsGoodByDefaultAndOnlyListedRevokedSerialIsRevoked() throws Exception {
        service.setTimes(new OcspService.Times(SIMULATED, null));
        service.putStatus(
                "issuer",
                "11",
                new OcspService.StatusEntry(null, "REVOKED", SIMULATED.minusSeconds(60), null));

        BasicOCSPResp basic =
                (BasicOCSPResp)
                        new OCSPResp(
                                        service.respond(
                                                request(
                                                        id(fixture.issuer(), 0x11),
                                                        id(fixture.issuer(), 0x12),
                                                        id(fixture.issuer(), 0x13))))
                                .getResponseObject();

        assertThat(basic.getResponses()[0].getCertStatus()).isInstanceOf(RevokedStatus.class);
        assertThat(basic.getResponses()[1].getCertStatus()).isNull();
        assertThat(basic.getResponses()[2].getCertStatus()).isNull();
    }

    @Test
    void noConfiguredStatusesMeansEveryCertificateOfTheIssuerIsGood() throws Exception {
        service.setTimes(new OcspService.Times(SIMULATED, null));

        BasicOCSPResp basic =
                (BasicOCSPResp)
                        new OCSPResp(service.respond(request(id(fixture.issuer(), 0x7F))))
                                .getResponseObject();

        assertThat(service.statuses("issuer")).isEmpty();
        assertThat(basic.getResponses()[0].getCertStatus()).isNull();
    }

    @Test
    void explicitUnknownStatusStillOverridesTheGoodDefault() throws Exception {
        service.setTimes(new OcspService.Times(SIMULATED, null));
        service.putStatus("issuer", "20", new OcspService.StatusEntry(null, "UNKNOWN", null, null));

        BasicOCSPResp basic =
                (BasicOCSPResp)
                        new OCSPResp(service.respond(request(id(fixture.issuer(), 0x20))))
                                .getResponseObject();

        assertThat(basic.getResponses()[0].getCertStatus()).isInstanceOf(UnknownStatus.class);
    }

    @Test
    void removingRevokedStatusRestoresTheGoodDefault() throws Exception {
        service.setTimes(new OcspService.Times(SIMULATED, null));
        service.putStatus(
                "issuer",
                "30",
                new OcspService.StatusEntry(null, "REVOKED", SIMULATED.minusSeconds(60), null));
        service.deleteStatus("issuer", "30");

        BasicOCSPResp basic =
                (BasicOCSPResp)
                        new OCSPResp(service.respond(request(id(fixture.issuer(), 0x30))))
                                .getResponseObject();

        assertThat(basic.getResponses()[0].getCertStatus()).isNull();
    }

    @Test
    void unknownIssuerIsStillUnauthorizedDespiteTheGoodDefault() throws Exception {
        Fixture other = fixture("EC", true);

        assertThat(new OCSPResp(service.respond(request(id(other.issuer(), 1)))).getStatus())
                .isEqualTo(OCSPRespBuilder.UNAUTHORIZED);
    }

    @Test
    void rejectsUnsupportedAutomaticSigningKey() {
        PrivateKey key = mock(PrivateKey.class);
        when(key.getAlgorithm()).thenReturn("XDH");
        assertThatThrownBy(() -> SigningAlgorithm.auto(key, "OCSP"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unsupported OCSP signing key algorithm: XDH");
    }

    @Test
    void acceptsDirectCaWithoutDigitalSignatureKeyUsageAndRejectsDelegatedWithoutIt()
            throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair caKeys = generator.generateKeyPair();
        KeyPair signerKeys = generator.generateKeyPair();
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withECDSA");
        X500Name caName = new X500Name("CN=Strict KeyUsage CA");
        Date from = Date.from(Instant.parse("2025-01-01T00:00:00Z"));
        Date until = Date.from(Instant.parse("2030-01-01T00:00:00Z"));

        JcaX509v3CertificateBuilder caBuilder =
                new JcaX509v3CertificateBuilder(
                        caName, BigInteger.ONE, from, until, caName, caKeys.getPublic());
        caBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        caBuilder.addExtension(
                Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        X509Certificate caCert =
                new JcaX509CertificateConverter()
                        .getCertificate(caBuilder.build(signerBuilder.build(caKeys.getPrivate())));

        KeyStore caStore = KeyStore.getInstance("PKCS12");
        caStore.load(null, null);
        caStore.setKeyEntry(
                "ca", caKeys.getPrivate(), "password".toCharArray(), new Certificate[] {caCert});
        ByteArrayOutputStream caOut = new ByteArrayOutputStream();
        caStore.store(caOut, "password".toCharArray());

        service.putProfile(
                "direct-ca", caOut.toByteArray(), "password", null, null, caCert.getEncoded());
        service.setTimes(new OcspService.Times(SIMULATED, null));
        OCSPResp response = new OCSPResp(service.respond(request(id(caCert, 1))));
        assertThat(response.getStatus()).isEqualTo(OCSPRespBuilder.SUCCESSFUL);

        JcaX509v3CertificateBuilder delegatedBuilder =
                new JcaX509v3CertificateBuilder(
                        caName,
                        BigInteger.TWO,
                        from,
                        until,
                        new X500Name("CN=Non-Signing Delegated"),
                        signerKeys.getPublic());
        delegatedBuilder.addExtension(
                Extension.basicConstraints, true, new BasicConstraints(false));
        delegatedBuilder.addExtension(
                Extension.keyUsage, true, new KeyUsage(KeyUsage.keyEncipherment));
        delegatedBuilder.addExtension(
                Extension.extendedKeyUsage,
                false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
        X509Certificate delegatedCert =
                new JcaX509CertificateConverter()
                        .getCertificate(
                                delegatedBuilder.build(signerBuilder.build(caKeys.getPrivate())));
        KeyStore delStore = KeyStore.getInstance("PKCS12");
        delStore.load(null, null);
        delStore.setKeyEntry(
                "ocsp",
                signerKeys.getPrivate(),
                "password".toCharArray(),
                new Certificate[] {delegatedCert, caCert});
        ByteArrayOutputStream delOut = new ByteArrayOutputStream();
        delStore.store(delOut, "password".toCharArray());

        assertThatThrownBy(
                        () ->
                                service.putProfile(
                                        "direct-ca",
                                        delOut.toByteArray(),
                                        "password",
                                        null,
                                        null,
                                        caCert.getEncoded()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Signer certificate does not permit digital signatures");
    }

    @Test
    void rejectsIssuerPemBundleWithMultipleCertificates() throws Exception {
        String pem =
                "-----BEGIN CERTIFICATE-----\n"
                        + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                                .encodeToString(fixture.issuer().getEncoded())
                        + "\n-----END CERTIFICATE-----\n";
        byte[] bundle = (pem + pem).getBytes(StandardCharsets.US_ASCII);

        assertThatThrownBy(
                        () ->
                                service.putProfile(
                                        "bundle", fixture.store(), "password", null, null, bundle))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Exactly one issuer certificate is required");
    }

    @Test
    void rejectsUnsupportedOcspRequestVersion() throws Exception {
        byte[] v2Request =
                new DERSequence(
                                new DERSequence(
                                        new ASN1Encodable[] {
                                            new DERTaggedObject(true, 0, new ASN1Integer(1)),
                                            new DERSequence(
                                                    new Request(
                                                            id(fixture.issuer(), 1)
                                                                    .toASN1Primitive(),
                                                            null))
                                        }))
                        .getEncoded();

        assertThat(new OCSPResp(service.respond(v2Request)).getStatus())
                .isEqualTo(OCSPRespBuilder.MALFORMED_REQUEST);
    }
}
