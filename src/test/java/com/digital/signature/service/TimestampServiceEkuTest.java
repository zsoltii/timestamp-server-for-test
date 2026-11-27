package com.digital.signature.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.digital.signature.config.TimeStampConfig;
import com.digital.signature.util.EkuTestKeystore;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.MessageDigest;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TimestampServiceEkuTest {
    private TimestampService service;

    @BeforeEach
    void setUp() {
        service = new TimestampService(new TimeStampConfig());
        service.init();
    }

    @Test
    void noncriticalEkuWithOptInSignsWithOriginalCertificateAndHash() throws Exception {
        byte[] keystore = EkuTestKeystore.create(false, KeyPurposeId.id_kp_timeStamping);
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(new ByteArrayInputStream(keystore), "password".toCharArray());
        byte[] original = store.getCertificate("signer").getEncoded();

        service.updateSigningKey(keystore, "password", null, "signer", false);
        assertThat(service.getSigningCertificate()).isEqualTo(original);

        TimeStampRequestGenerator generator = new TimeStampRequestGenerator();
        generator.setCertReq(true);
        byte[] imprint = MessageDigest.getInstance("SHA-256").digest(new byte[] {1, 2, 3});
        TimeStampRequest request =
                generator.generate(NISTObjectIdentifiers.id_sha256, imprint, BigInteger.ONE);
        TimeStampResponse response =
                new TimeStampResponse(service.generateTimestampResponse(request.getEncoded()));
        response.validate(request);
        assertThat(response.getStatus()).isZero();
        TimeStampToken token = response.getTimeStampToken();
        X509CertificateHolder embedded = token.getCertificates().getMatches(null).iterator().next();
        assertThat(embedded.getEncoded()).isEqualTo(original);
        assertThat(
                        embedded.getExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage)
                                .isCritical())
                .isFalse();
        SignerInformation signer =
                token.toCMSSignedData().getSignerInfos().getSigners().iterator().next();
        assertThat(signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(embedded)))
                .isTrue();
        SigningCertificate signingCertificate =
                SigningCertificate.getInstance(
                        signer.getSignedAttributes()
                                .get(PKCSObjectIdentifiers.id_aa_signingCertificate)
                                .getAttrValues()
                                .getObjectAt(0));
        assertThat(signingCertificate.getCerts()[0].getCertHash())
                .isEqualTo(MessageDigest.getInstance("SHA-1").digest(original));
    }

    @Test
    void strictDefaultAndExplicitTrueRejectNoncriticalEkuWithoutChangingCertificate()
            throws Exception {
        byte[] keystore = EkuTestKeystore.create(false, KeyPurposeId.id_kp_timeStamping);
        byte[] before = service.getSigningCertificate();
        assertThatThrownBy(() -> service.updateSigningKey(keystore, "password", null, "signer"))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(
                        () -> service.updateSigningKey(keystore, "password", null, "signer", true))
                .isInstanceOf(IllegalStateException.class);
        assertThat(service.getSigningCertificate()).isEqualTo(before);
        TimeStampRequest request =
                new TimeStampRequestGenerator()
                        .generate(NISTObjectIdentifiers.id_sha256, new byte[32], BigInteger.ONE);
        TimeStampResponse response =
                new TimeStampResponse(service.generateTimestampResponse(request.getEncoded()));
        assertThat(response.getStatus()).isZero();
    }

    @Test
    void criticalEkuWorksInBothModes() throws Exception {
        byte[] keystore = EkuTestKeystore.create(true, KeyPurposeId.id_kp_timeStamping);
        service.updateSigningKey(keystore, "password", null, "signer", true);
        byte[] certificate = service.getSigningCertificate();
        service.updateSigningKey(keystore, "password", null, "signer", false);
        assertThat(service.getSigningCertificate()).isEqualTo(certificate);
    }

    @Test
    void relaxedModeStillRejectsMissingWrongAndMultiplePurposes() throws Exception {
        byte[] before = service.getSigningCertificate();
        byte[][] invalid = {
            EkuTestKeystore.create(false),
            EkuTestKeystore.create(false, KeyPurposeId.id_kp_serverAuth),
            EkuTestKeystore.create(
                    false, KeyPurposeId.id_kp_timeStamping, KeyPurposeId.id_kp_serverAuth)
        };
        for (byte[] keystore : invalid) {
            assertThatThrownBy(
                            () ->
                                    service.updateSigningKey(
                                            keystore, "password", null, "signer", false))
                    .isInstanceOf(IllegalStateException.class);
            assertThat(service.getSigningCertificate()).isEqualTo(before);
        }
    }

    @Test
    void relaxedModeRejectsBadKeystorePassword() throws Exception {
        byte[] keystore = EkuTestKeystore.create(false, KeyPurposeId.id_kp_timeStamping);
        assertThatThrownBy(() -> service.updateSigningKey(keystore, "wrong", null, "signer", false))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> service.updateSigningKey(keystore, "", null, "signer", false))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void relaxedModeRejectsNullOrEmptyRequiredInput() throws Exception {
        byte[] keystore = EkuTestKeystore.create(false, KeyPurposeId.id_kp_timeStamping);
        assertThatThrownBy(() -> service.updateSigningKey(null, "password", null, "signer", false))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(
                        () ->
                                service.updateSigningKey(
                                        new byte[0], "password", null, "signer", false))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.updateSigningKey(keystore, null, null, "signer", false))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
