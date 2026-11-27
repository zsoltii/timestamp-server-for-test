package com.digital.signature.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.digital.signature.config.TimeStampConfig;
import com.digital.signature.util.TestKeystoreGenerator;
import java.nio.file.Files;
import java.nio.file.Path;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class TimestampSigningAlgorithmsTest {

    @TempDir Path tempDir;

    @ParameterizedTest
    @CsvSource({
        "RSA, 2048, SHA256withRSA",
        "RSASSA-PSS, 2048, SHA256withRSAandMGF1",
        "EC, 256, SHA256withECDSA",
        "DSA, 2048, SHA256withDSA",
        "Ed25519, 0, Ed25519",
        "Ed448, 0, Ed448",
        "ML-DSA-44, 0, ML-DSA-44",
        "ML-DSA-65, 0, ML-DSA-65",
        "ML-DSA-87, 0, ML-DSA-87"
    })
    void signsAndVerifiesAfterKeyUpdate(String keyAlgorithm, int keySize, String signatureAlgorithm)
            throws Exception {
        final TimestampService service = new TimestampService(new TimeStampConfig());
        service.init();
        final Path keystore = tempDir.resolve("signer.p12");
        TestKeystoreGenerator.generateTestKeystore(
                keystore.toString(),
                "password",
                "signer",
                "password",
                keyAlgorithm,
                keySize,
                signatureAlgorithm);

        service.updateSigningKey(Files.readAllBytes(keystore), "password", null, "signer");

        final TimeStampRequestGenerator generator = new TimeStampRequestGenerator();
        generator.setCertReq(true);
        final TimeStampRequest request =
                generator.generate(NISTObjectIdentifiers.id_sha256, new byte[32]);
        final TimeStampResponse response =
                new TimeStampResponse(service.generateTimestampResponse(request.getEncoded()));
        response.validate(request);
        assertThat(response.getStatus()).isZero();
        final TimeStampToken token = response.getTimeStampToken();
        final SignerInformation signer =
                token.toCMSSignedData().getSignerInfos().getSigners().iterator().next();
        assertThat(signer.getEncryptionAlgOID())
                .isEqualTo(
                        new DefaultSignatureAlgorithmIdentifierFinder()
                                .find(signatureAlgorithm)
                                .getAlgorithm()
                                .getId());
        final JcaSimpleSignerInfoVerifierBuilder verifier =
                new JcaSimpleSignerInfoVerifierBuilder();
        if ("RSASSA-PSS".equals(keyAlgorithm)) {
            verifier.setProvider(new BouncyCastleProvider());
        }
        token.validate(verifier.build(new X509CertificateHolder(service.getSigningCertificate())));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = " ")
    void rejectsBlankSignatureAlgorithm(String signatureAlgorithm) {
        final TimeStampConfig config = new TimeStampConfig();
        config.setSignatureAlgorithm(signatureAlgorithm);
        final TimestampService service = new TimestampService(config);

        assertThatThrownBy(service::init)
                .isInstanceOf(IllegalStateException.class)
                .hasRootCauseMessage("timestamp.signature-algorithm must not be blank");
    }

    @Test
    void rejectsKeyAgreementAlgorithmAsTimestampSigner() {
        final TimeStampConfig config = new TimeStampConfig();
        config.setKeyAlgorithm("XDH");
        config.setKeySize(255);
        final TimestampService service = new TimestampService(config);

        assertThatThrownBy(service::init)
                .isInstanceOf(IllegalStateException.class)
                .hasRootCauseMessage("Unsupported timestamp signing key algorithm: XDH");
    }

    @Test
    void explicitIncompatibleAlgorithmRejectsUpdateWithoutReplacingCertificate() throws Exception {
        final TimeStampConfig config = new TimeStampConfig();
        config.setSignatureAlgorithm("SHA384withRSA");
        final TimestampService service = new TimestampService(config);
        service.init();
        final byte[] originalCertificate = service.getSigningCertificate();
        final Path keystore = tempDir.resolve("ec.p12");
        TestKeystoreGenerator.generateTestKeystoreWithEC(
                keystore.toString(), "password", "signer", "password");
        final byte[] replacement = Files.readAllBytes(keystore);

        assertThatThrownBy(() -> service.updateSigningKey(replacement, "password", null, "signer"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Failed to update signing key");
        assertThat(service.getSigningCertificate()).isEqualTo(originalCertificate);
    }
}
