package com.digital.signature.util;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Creates PKCS12 fixtures with controlled timestamping EKU extensions. */
public final class EkuTestKeystore {
    private EkuTestKeystore() {}

    public static byte[] create(boolean critical, KeyPurposeId... purposes) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        X500Name subject = new X500Name("CN=EKU test");
        long now = System.currentTimeMillis();
        JcaX509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(
                        subject,
                        BigInteger.valueOf(now),
                        new Date(now - 60000),
                        new Date(now + 86400000),
                        subject,
                        pair.getPublic());
        if (purposes.length > 0) {
            builder.addExtension(
                    Extension.extendedKeyUsage, critical, new ExtendedKeyUsage(purposes));
        }
        Certificate certificate =
                new JcaX509CertificateConverter()
                        .getCertificate(
                                builder.build(
                                        new JcaContentSignerBuilder("SHA256withRSA")
                                                .build(pair.getPrivate())));
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setKeyEntry(
                "signer",
                pair.getPrivate(),
                "password".toCharArray(),
                new Certificate[] {certificate});
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        store.store(output, "password".toCharArray());
        return output.toByteArray();
    }
}
