package com.digital.signature.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.digital.signature.config.TimeStampConfig;
import com.digital.signature.util.TestKeystoreGenerator;
import java.io.ByteArrayInputStream;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class SigningCertificateInfoTest {

    @TempDir Path tempDir;

    @Test
    void returnsInformationFromTheGeneratedCertificate() throws Exception {
        final TimestampService service = new TimestampService(new TimeStampConfig());
        service.init();
        final byte[] der = service.getSigningCertificate();
        final X509Certificate certificate =
                (X509Certificate)
                        CertificateFactory.getInstance("X.509")
                                .generateCertificate(new ByteArrayInputStream(der));

        final SigningCertificateInfo info = service.getSigningCertificateInfo();

        assertThat(info.subject()).isEqualTo(certificate.getSubjectX500Principal().getName());
        assertThat(info.issuer()).isEqualTo(certificate.getIssuerX500Principal().getName());
        assertThat(info.serialNumber())
                .isEqualTo(certificate.getSerialNumber().toString(16).toUpperCase());
        assertThat(info.validFrom()).isEqualTo(certificate.getNotBefore().toInstant());
        assertThat(info.validUntil()).isEqualTo(certificate.getNotAfter().toInstant());
        assertThat(info.sha256Fingerprint())
                .isEqualTo(
                        HexFormat.of()
                                .withUpperCase()
                                .formatHex(MessageDigest.getInstance("SHA-256").digest(der)));
        assertThat(info.publicKeyAlgorithm()).isEqualTo("RSA");
        assertThat(info.publicKeySizeBits()).isEqualTo(2048);
        assertThat(info.publicKeyParameters()).isNull();
    }

    @Test
    void rejectsUninitializedCertificate() {
        final TimestampService service = new TimestampService(new TimeStampConfig());

        assertThatThrownBy(service::getSigningCertificateInfo)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Signing certificate not initialized");
    }

    @Test
    void informationReadUsesTheSameLockAsKeyUpdates() throws Exception {
        assertThat(
                        Modifier.isSynchronized(
                                TimestampService.class
                                        .getMethod("getSigningCertificateInfo")
                                        .getModifiers()))
                .isTrue();
        assertThat(
                        Modifier.isSynchronized(
                                TimestampService.class
                                        .getMethod(
                                                "updateSigningKey",
                                                byte[].class,
                                                String.class,
                                                String.class,
                                                String.class,
                                                boolean.class)
                                        .getModifiers()))
                .isTrue();
    }

    @ParameterizedTest
    @CsvSource({
        "RSA, 2048, SHA256withRSA, RSA, 2048",
        "RSASSA-PSS, 2048, SHA256withRSAandMGF1, RSASSA-PSS, 2048",
        "EC, 256, SHA256withECDSA, EC, 256",
        "DSA, 2048, SHA256withDSA, DSA, 2048",
        "Ed25519, 0, Ed25519, EdDSA,",
        "Ed448, 0, Ed448, EdDSA,",
        "ML-DSA-44, 0, ML-DSA-44, ML-DSA,",
        "ML-DSA-65, 0, ML-DSA-65, ML-DSA,",
        "ML-DSA-87, 0, ML-DSA-87, ML-DSA,"
    })
    void reflectsNewCertificateAndKeepsItAfterFailedUpdate(
            String algorithm,
            int size,
            String signature,
            String expectedAlgorithm,
            Integer expectedSize)
            throws Exception {
        final TimestampService service = new TimestampService(new TimeStampConfig());
        service.init();
        final SigningCertificateInfo before = service.getSigningCertificateInfo();
        final Path keystore = tempDir.resolve("signer.p12");
        TestKeystoreGenerator.generateTestKeystore(
                keystore.toString(), "password", "signer", "password", algorithm, size, signature);
        final byte[] data = Files.readAllBytes(keystore);

        service.updateSigningKey(data, "password", null, "signer");

        final SigningCertificateInfo after = service.getSigningCertificateInfo();
        assertThat(after.sha256Fingerprint()).isNotEqualTo(before.sha256Fingerprint());
        assertThat(after.publicKeyAlgorithm()).isEqualTo(expectedAlgorithm);
        assertThat(after.publicKeySizeBits()).isEqualTo(expectedSize);
        if (algorithm.startsWith("Ed") || algorithm.startsWith("ML-DSA")) {
            assertThat(after.publicKeyParameters()).isEqualTo(algorithm);
        }

        assertThatThrownBy(() -> service.updateSigningKey(data, "bad-password", null, "signer"))
                .isInstanceOf(IllegalStateException.class);
        assertThat(service.getSigningCertificateInfo()).isEqualTo(after);
    }
}
