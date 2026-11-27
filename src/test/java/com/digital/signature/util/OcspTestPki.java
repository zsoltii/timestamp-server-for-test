package com.digital.signature.util;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/** Creates in-memory test CAs, OCSP signers, PKCS12 stores and OCSP requests. */
public final class OcspTestPki {
    public static final String PASSWORD = "password";
    public static final Instant DEFAULT_FROM = Instant.parse("2025-01-01T00:00:00Z");
    public static final Instant DEFAULT_UNTIL = Instant.parse("2030-01-01T00:00:00Z");
    private static final AtomicLong SERIALS = new AtomicLong(100);

    private OcspTestPki() {}

    /**
     * A test CA together with the key and certificate that sign its OCSP responses.
     *
     * @param keys CA key pair
     * @param certificate CA certificate
     * @param signerKeys OCSP signer key pair (the CA keys when the CA signs directly)
     * @param signer OCSP signer certificate (the CA certificate when the CA signs directly)
     */
    public record Ca(
            KeyPair keys, X509Certificate certificate, KeyPair signerKeys, X509Certificate signer) {

        /** Returns the PKCS12 store with the signer key and its chain. */
        public byte[] pkcs12() throws Exception {
            return store(
                    signerKeys,
                    signer.equals(certificate)
                            ? new Certificate[] {signer}
                            : new Certificate[] {signer, certificate});
        }

        /** Re-issues the CA certificate with the same name and key; the signer is kept. */
        public Ca renew(Instant from, Instant until) throws Exception {
            X509Certificate renewed =
                    caCertificate(
                            certificate.getSubjectX500Principal().getName(), keys, from, until);
            return new Ca(keys, renewed, signerKeys, signer.equals(certificate) ? renewed : signer);
        }
    }

    /** Creates a CA with a delegated OCSP signer valid for the default period. */
    public static Ca delegated(String subject) throws Exception {
        return create(subject, true, DEFAULT_FROM, DEFAULT_UNTIL);
    }

    /** Creates a CA that signs its own OCSP responses, valid for the default period. */
    public static Ca direct(String subject) throws Exception {
        return create(subject, false, DEFAULT_FROM, DEFAULT_UNTIL);
    }

    /** Creates a CA with the given validity, optionally with a delegated OCSP signer. */
    public static Ca create(String subject, boolean delegated, Instant from, Instant until)
            throws Exception {
        KeyPair keys = keyPair();
        X509Certificate ca = caCertificate(subject, keys, from, until);
        if (!delegated) {
            return new Ca(keys, ca, keys, ca);
        }
        KeyPair signerKeys = keyPair();
        JcaX509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(
                        new X500Name(subject),
                        BigInteger.valueOf(SERIALS.incrementAndGet()),
                        Date.from(from),
                        Date.from(until),
                        new X500Name("CN=OCSP signer of " + subject.replace("CN=", "")),
                        signerKeys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        builder.addExtension(
                Extension.extendedKeyUsage,
                false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
        return new Ca(keys, ca, signerKeys, sign(builder, keys));
    }

    /** Builds a CertID for a serial issued by the given CA with the given hash name. */
    public static CertificateID certId(X509Certificate issuer, BigInteger serial, String hash)
            throws Exception {
        AlgorithmIdentifier algorithm =
                switch (hash) {
                    case "SHA-1" -> CertificateID.HASH_SHA1;
                    case "SHA-256" -> new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
                    case "SHA-384" -> new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
                    case "SHA-512" -> new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512);
                    default -> throw new IllegalArgumentException("Unsupported hash: " + hash);
                };
        return new CertificateID(
                new JcaDigestCalculatorProviderBuilder().build().get(algorithm),
                new JcaX509CertificateHolder(issuer),
                serial);
    }

    /** Builds a DER OCSP request with a nonce for the given CertIDs. */
    public static byte[] request(List<CertificateID> ids) throws Exception {
        return request(ids, new byte[] {1, 2, 3, 4});
    }

    /** Builds a DER OCSP request with the given nonce for the given CertIDs. */
    public static byte[] request(List<CertificateID> ids, byte[] nonce) throws Exception {
        OCSPReqBuilder builder = new OCSPReqBuilder();
        for (CertificateID id : ids) {
            builder.addRequest(id);
        }
        builder.setRequestExtensions(
                new Extensions(
                        new Extension(
                                OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                                false,
                                new DEROctetString(nonce).getEncoded())));
        return builder.build().getEncoded();
    }

    private static KeyPair keyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        return generator.generateKeyPair();
    }

    private static X509Certificate caCertificate(
            String subject, KeyPair keys, Instant from, Instant until) throws Exception {
        X500Name name = new X500Name(subject);
        JcaX509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(
                        name,
                        BigInteger.valueOf(SERIALS.incrementAndGet()),
                        Date.from(from),
                        Date.from(until),
                        name,
                        keys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature));
        return sign(builder, keys);
    }

    private static X509Certificate sign(JcaX509v3CertificateBuilder builder, KeyPair issuer)
            throws Exception {
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(
                                new JcaContentSignerBuilder("SHA256withECDSA")
                                        .build(issuer.getPrivate())));
    }

    private static byte[] store(KeyPair keys, Certificate[] chain) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setKeyEntry("ocsp", keys.getPrivate(), PASSWORD.toCharArray(), chain);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        store.store(output, PASSWORD.toCharArray());
        return output.toByteArray();
    }
}
