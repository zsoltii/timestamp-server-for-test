package com.digital.signature.service;

import java.security.PrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Locale;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

final class SigningAlgorithm {
    private static final BouncyCastleProvider PSS_PROVIDER = new BouncyCastleProvider();

    private SigningAlgorithm() {}

    /* default */ static JcaContentSignerBuilder auto(final PrivateKey key, final String purpose) {
        final String keyAlgorithm = key.getAlgorithm().toUpperCase(Locale.ROOT);
        final String algorithm =
                ("EDDSA".equals(keyAlgorithm) || "ML-DSA".equals(keyAlgorithm))
                                && key.getParams() instanceof NamedParameterSpec named
                        ? named.getName()
                        : keyAlgorithm;
        return switch (algorithm.toUpperCase(Locale.ROOT)) {
            case "RSA" -> new JcaContentSignerBuilder("SHA256withRSA");
            case "RSASSA-PSS" -> pss(key);
            case "EC", "ECDSA" -> new JcaContentSignerBuilder("SHA256withECDSA");
            case "DSA" -> new JcaContentSignerBuilder("SHA256withDSA");
            case "ED25519" -> new JcaContentSignerBuilder("Ed25519");
            case "ED448" -> new JcaContentSignerBuilder("Ed448");
            case "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" -> new JcaContentSignerBuilder(algorithm);
            default ->
                    throw new IllegalArgumentException(
                            "Unsupported " + purpose + " signing key algorithm: " + algorithm);
        };
    }

    private static JcaContentSignerBuilder pss(final PrivateKey key) {
        final PSSParameterSpec parameters =
                key.getParams() instanceof PSSParameterSpec pss
                        ? pss
                        : new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
        return new JcaContentSignerBuilder("RSASSA-PSS", parameters).setProvider(PSS_PROVIDER);
    }
}
