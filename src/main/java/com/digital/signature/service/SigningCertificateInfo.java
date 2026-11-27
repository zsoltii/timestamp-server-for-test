package com.digital.signature.service;

import java.time.Instant;

/**
 * Public information about the current signing certificate and its public key.
 *
 * @param subject certificate subject
 * @param issuer certificate issuer
 * @param serialNumber hexadecimal certificate serial number
 * @param validFrom beginning of the certificate validity period
 * @param validUntil end of the certificate validity period
 * @param sha256Fingerprint SHA-256 digest of the DER-encoded certificate
 * @param publicKeyAlgorithm public key algorithm
 * @param publicKeySizeBits key size in bits, or null when it cannot be determined
 * @param publicKeyParameters named key parameters, or null when unavailable
 */
public record SigningCertificateInfo(
        String subject,
        String issuer,
        String serialNumber,
        Instant validFrom,
        Instant validUntil,
        String sha256Fingerprint,
        String publicKeyAlgorithm,
        Integer publicKeySizeBits,
        String publicKeyParameters) {}
