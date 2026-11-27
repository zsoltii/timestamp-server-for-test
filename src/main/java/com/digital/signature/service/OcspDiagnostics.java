package com.digital.signature.service;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Locale;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;

/**
 * Builds human readable descriptions for OCSP diagnostic log messages, so a rejected request or a
 * wrong configuration can be traced from the log alone. No private key material is described.
 */
final class OcspDiagnostics {
    private static final HexFormat HEX = HexFormat.of();

    private OcspDiagnostics() {}

    /** Returns the hexadecimal (upper case) form of a serial number. */
    /* default */ static String serialHex(final BigInteger serial) {
        return serial.toString(16).toUpperCase(Locale.ROOT);
    }

    /** Returns the RFC 6960 name of an OCSP response status, e.g. "unauthorized". */
    /* default */ static String responseStatusName(final int status) {
        final String[] names = {
            "successful",
            "malformedRequest",
            "internalError",
            "tryLater",
            "status 4",
            "sigRequired",
            "unauthorized"
        };
        return status >= 0 && status < names.length ? names[status] : "status " + status;
    }

    /** Returns a readable name of a CertID hash algorithm, or its OID when unknown. */
    /* default */ static String hashName(final ASN1ObjectIdentifier oid) {
        String name = oid.getId();
        if (OIWObjectIdentifiers.idSHA1.equals(oid)) {
            name = "SHA-1";
        } else if (NISTObjectIdentifiers.id_sha256.equals(oid)) {
            name = "SHA-256";
        } else if (NISTObjectIdentifiers.id_sha512.equals(oid)) {
            name = "SHA-512";
        }
        return name;
    }

    /** Describes a CertID: serial, hash algorithm and the issuer hashes. */
    /* default */ static String describe(final CertificateID certId) {
        return "serial="
                + serialHex(certId.getSerialNumber())
                + " hash="
                + hashName(certId.getHashAlgOID())
                + " issuerNameHash="
                + HEX.formatHex(certId.getIssuerNameHash())
                + " issuerKeyHash="
                + HEX.formatHex(certId.getIssuerKeyHash());
    }

    /**
     * Compares a CertID with the issuer of a profile and explains the difference.
     *
     * @return the expected hashes of the profile and a verdict such as "different issuer"
     */
    /* default */ static String compare(
            final String profileId,
            final X509CertificateHolder issuer,
            final CertificateID certId,
            final DigestCalculatorProvider digests) {
        String result;
        try {
            final CertificateID expected =
                    new CertificateID(
                            digests.get(new AlgorithmIdentifier(certId.getHashAlgOID())),
                            issuer,
                            BigInteger.ONE);
            final boolean sameName =
                    Arrays.equals(expected.getIssuerNameHash(), certId.getIssuerNameHash());
            final boolean sameKey =
                    Arrays.equals(expected.getIssuerKeyHash(), certId.getIssuerKeyHash());
            result =
                    "profile '"
                            + profileId
                            + "' ("
                            + issuer.getSubject()
                            + ") expects issuerNameHash="
                            + HEX.formatHex(expected.getIssuerNameHash())
                            + " issuerKeyHash="
                            + HEX.formatHex(expected.getIssuerKeyHash())
                            + " -> "
                            + verdict(sameName, sameKey);
        } catch (OCSPException | OperatorCreationException e) {
            result =
                    "profile '"
                            + profileId
                            + "': cannot compute the expected issuer hashes: "
                            + e.getMessage();
        }
        return result;
    }

    private static String verdict(final boolean sameName, final boolean sameKey) {
        String verdict = "different issuer (wrong issuer certificate uploaded?)";
        if (sameName && sameKey) {
            verdict = "matches";
        } else if (sameName) {
            verdict = "same issuer name but different key (another or re-keyed CA?)";
        } else if (sameKey) {
            verdict = "same key but different issuer name encoding";
        }
        return verdict;
    }

    /**
     * Checks that a certificate is valid at the given instant.
     *
     * @return null when valid, otherwise the explanation
     */
    /* default */ static String validityProblem(
            final String role, final X509Certificate certificate, final Instant instant) {
        final Instant notBefore = certificate.getNotBefore().toInstant();
        final Instant notAfter = certificate.getNotAfter().toInstant();
        String problem = null;
        if (instant.isBefore(notBefore) || instant.isAfter(notAfter)) {
            problem =
                    "the "
                            + role
                            + " certificate "
                            + certificate.getSubjectX500Principal().getName()
                            + " is not valid at thisUpdate "
                            + instant
                            + " (valid from "
                            + notBefore
                            + " to "
                            + notAfter
                            + "); change the simulated OCSP time or upload a valid certificate";
        }
        return problem;
    }
}
