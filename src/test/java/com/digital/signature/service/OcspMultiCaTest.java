package com.digital.signature.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.digital.signature.util.OcspTestPki;
import com.digital.signature.util.OcspTestPki.Ca;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class OcspMultiCaTest {
    private static final Instant SIMULATED = Instant.parse("2029-01-01T00:00:00Z");
    private static final BigInteger SERIAL = BigInteger.valueOf(0x1A);
    private OcspService service;

    @BeforeEach
    void setUp() {
        service = new OcspService();
        service.setTimes(new OcspService.Times(SIMULATED, null));
    }

    private void upload(String id, Ca ca) throws Exception {
        service.putProfile(
                id, ca.pkcs12(), OcspTestPki.PASSWORD, null, null, ca.certificate().getEncoded());
    }

    private OCSPResp respond(CertificateID... ids) throws Exception {
        return new OCSPResp(service.respond(OcspTestPki.request(List.of(ids))));
    }

    private static CertificateID id(Ca ca, BigInteger serial) throws Exception {
        return OcspTestPki.certId(ca.certificate(), serial, "SHA-1");
    }

    private static boolean signedBy(OCSPResp response, X509Certificate signer) throws Exception {
        return ((BasicOCSPResp) response.getResponseObject())
                .isSignatureValid(
                        new JcaContentVerifierProviderBuilder().build(signer.getPublicKey()));
    }

    @Test
    void issuerIdentityIsSharedByRenewedCertificate() throws Exception {
        Ca ca = OcspTestPki.direct("CN=Identity CA");
        Ca renewed = ca.renew(OcspTestPki.DEFAULT_FROM, Instant.parse("2031-01-01T00:00:00Z"));

        assertThat(renewed.certificate()).isNotEqualTo(ca.certificate());
        assertThat(OcspService.issuerIdentity(renewed.certificate()))
                .isEqualTo(OcspService.issuerIdentity(ca.certificate()));
    }

    @Test
    void issuerIdentityDiffersForOtherKeyOrName() throws Exception {
        Ca first = OcspTestPki.direct("CN=Identity CA");
        Ca sameName = OcspTestPki.direct("CN=Identity CA");
        Ca otherName = OcspTestPki.direct("CN=Other CA");

        assertThat(OcspService.issuerIdentity(sameName.certificate()))
                .isNotEqualTo(OcspService.issuerIdentity(first.certificate()));
        assertThat(OcspService.issuerIdentity(otherName.certificate()))
                .isNotEqualTo(OcspService.issuerIdentity(first.certificate()));
    }

    @Test
    void issuerIdentityRejectsNull() {
        assertThatThrownBy(() -> OcspService.issuerIdentity(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Issuer certificate is required");
    }

    @Test
    void sameNamedCasWithDifferentKeysKeepSeparateStatuses() throws Exception {
        Ca a = OcspTestPki.delegated("CN=Shared CA");
        Ca b = OcspTestPki.delegated("CN=Shared CA");
        upload("a", a);
        upload("b", b);
        service.putStatus("a", "1A", new OcspService.StatusEntry(null, "GOOD", null, null));
        service.putStatus(
                "b",
                "1A",
                new OcspService.StatusEntry(null, "REVOKED", SIMULATED.minusSeconds(60), 1));

        OCSPResp fromA = respond(id(a, SERIAL));
        OCSPResp fromB = respond(id(b, SERIAL));

        assertThat(fromA.getStatus()).isEqualTo(OCSPRespBuilder.SUCCESSFUL);
        assertThat(((BasicOCSPResp) fromA.getResponseObject()).getResponses()[0].getCertStatus())
                .isNull();
        assertThat(signedBy(fromA, a.signer())).isTrue();
        assertThat(signedBy(fromA, b.signer())).isFalse();
        assertThat(((BasicOCSPResp) fromB.getResponseObject()).getResponses()[0].getCertStatus())
                .isInstanceOf(RevokedStatus.class);
        assertThat(signedBy(fromB, b.signer())).isTrue();
    }

    @Test
    void sameIdentityUnderAnotherProfileIdIsRejected() throws Exception {
        Ca ca = OcspTestPki.delegated("CN=Renewed CA");
        upload("a", ca);
        service.putStatus("a", "1A", new OcspService.StatusEntry(null, "GOOD", null, null));
        Ca renewed = ca.renew(OcspTestPki.DEFAULT_FROM, Instant.parse("2031-01-01T00:00:00Z"));

        assertThatThrownBy(() -> upload("a2", renewed))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Issuer already has a profile: a");
        assertThat(service.profiles()).extracting(OcspService.ProfileInfo::id).containsExactly("a");
        assertThat(service.statuses("a")).hasSize(1);
    }

    @Test
    void renewalUnderSameProfileIdKeepsStatuses() throws Exception {
        Ca ca = OcspTestPki.direct("CN=Renewed CA");
        upload("a", ca);
        service.putStatus("a", "1A", new OcspService.StatusEntry(null, "GOOD", null, null));
        Ca renewed = ca.renew(OcspTestPki.DEFAULT_FROM, Instant.parse("2031-01-01T00:00:00Z"));

        upload("a", renewed);

        assertThat(service.statuses("a")).hasSize(1);
        OCSPResp response = respond(id(renewed, SERIAL));
        assertThat(response.getStatus()).isEqualTo(OCSPRespBuilder.SUCCESSFUL);
        assertThat(((BasicOCSPResp) response.getResponseObject()).getCerts()[0].getEncoded())
                .isEqualTo(renewed.certificate().getEncoded());
    }

    @Test
    void replacingProfileWithAnotherCaClearsStatuses() throws Exception {
        upload("a", OcspTestPki.delegated("CN=First CA"));
        service.putStatus("a", "1A", new OcspService.StatusEntry(null, "GOOD", null, null));

        upload("a", OcspTestPki.delegated("CN=Second CA"));

        assertThat(service.statuses("a")).isEmpty();
    }

    @Test
    void renewalWithOldCaCertificateInPkcs12IsRejectedAndOldProfileKept() throws Exception {
        Ca ca = OcspTestPki.direct("CN=Direct CA");
        upload("a", ca);
        service.putStatus("a", "1A", new OcspService.StatusEntry(null, "GOOD", null, null));
        Ca renewed = ca.renew(OcspTestPki.DEFAULT_FROM, Instant.parse("2031-01-01T00:00:00Z"));

        assertThatThrownBy(
                        () ->
                                service.putProfile(
                                        "a",
                                        ca.pkcs12(),
                                        OcspTestPki.PASSWORD,
                                        null,
                                        null,
                                        renewed.certificate().getEncoded()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("PKCS12 certificate does not match the uploaded issuer certificate");
        assertThat(service.statuses("a")).hasSize(1);
        OCSPResp response = respond(id(ca, SERIAL));
        assertThat(response.getStatus()).isEqualTo(OCSPRespBuilder.SUCCESSFUL);
        assertThat(signedBy(response, ca.certificate())).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"SHA-1", "SHA-256", "SHA-512"})
    void everySupportedCertIdHashSelectsTheRightProfile(String hash) throws Exception {
        Ca a = OcspTestPki.delegated("CN=Hash CA A");
        Ca b = OcspTestPki.delegated("CN=Hash CA B");
        upload("a", a);
        upload("b", b);

        OCSPResp response = respond(OcspTestPki.certId(b.certificate(), BigInteger.ONE, hash));

        assertThat(response.getStatus()).isEqualTo(OCSPRespBuilder.SUCCESSFUL);
        assertThat(signedBy(response, b.signer())).isTrue();
    }

    @Test
    void severalCertificatesOfOneCaAreAnsweredTogether() throws Exception {
        Ca a = OcspTestPki.delegated("CN=Batch CA");
        upload("a", a);

        OCSPResp response = respond(id(a, BigInteger.ONE), id(a, BigInteger.TWO));

        assertThat(response.getStatus()).isEqualTo(OCSPRespBuilder.SUCCESSFUL);
        assertThat(((BasicOCSPResp) response.getResponseObject()).getResponses()).hasSize(2);
    }

    @Test
    void mixedAndUnknownIssuersAreUnauthorized() throws Exception {
        Ca a = OcspTestPki.delegated("CN=Mixed CA A");
        Ca b = OcspTestPki.delegated("CN=Mixed CA B");
        upload("a", a);
        upload("b", b);

        assertThat(respond(id(a, BigInteger.ONE), id(b, BigInteger.TWO)).getStatus())
                .isEqualTo(OCSPRespBuilder.UNAUTHORIZED);
        assertThat(respond(id(OcspTestPki.delegated("CN=Unknown CA"), BigInteger.ONE)).getStatus())
                .isEqualTo(OCSPRespBuilder.UNAUTHORIZED);
    }

    @Test
    void expiredCaFailsWithoutAffectingAnotherCa() throws Exception {
        Ca expired =
                OcspTestPki.create(
                        "CN=Expired CA",
                        true,
                        OcspTestPki.DEFAULT_FROM,
                        Instant.parse("2028-12-31T00:00:00Z"));
        Ca valid = OcspTestPki.delegated("CN=Valid CA");
        upload("expired", expired);
        upload("valid", valid);

        assertThat(respond(id(expired, BigInteger.ONE)).getStatus())
                .isEqualTo(OCSPRespBuilder.INTERNAL_ERROR);
        assertThat(respond(id(valid, BigInteger.ONE)).getStatus())
                .isEqualTo(OCSPRespBuilder.SUCCESSFUL);
    }
}
