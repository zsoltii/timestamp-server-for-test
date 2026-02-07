package com.digital.signature.service;

import jakarta.annotation.PostConstruct;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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
import org.springframework.stereotype.Service;

@Service
public class TimestampService {

    private TimeStampResponseGenerator timeStampResponseGenerator;

    @PostConstruct
    public void init() {
        try {
            // 1. Kulcspár generálás (RSA 2048) teszt célra
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // 2. Önaláírt tanúsítvány generálás
            X500Name subject =
                    new X500Name("CN=Test Timestamp Authority, O=Digital Signature, C=HU");
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
            Date notBefore = Date.from(Instant.now());
            Date notAfter = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));

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
                    new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
            X509CertificateHolder certificateHolder = certBuilder.build(contentSigner);

            // 3. TimeStampResponseGenerator inicializálás
            // Teszt policy OID
            ASN1ObjectIdentifier policyId = new ASN1ObjectIdentifier("1.3.6.1.4.1.13762.3");

            DigestCalculatorProvider digestCalculatorProvider =
                    new JcaDigestCalculatorProviderBuilder().build();

            // SignerInfoGenerator létrehozása
            SignerInfoGenerator signerInfoGenerator =
                    new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider)
                            .build(contentSigner, certificateHolder);

            // DigestCalculator létrehozása (SHA-1 a timestamp tokenhez)
            DigestCalculator digestCalculator =
                    digestCalculatorProvider.get(
                            new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

            TimeStampTokenGenerator tokenGenerator =
                    new TimeStampTokenGenerator(signerInfoGenerator, digestCalculator, policyId);

            // Tanúsítványok hozzáadása Store-ként
            List<X509CertificateHolder> certs = new ArrayList<>();
            certs.add(certificateHolder);
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
}
