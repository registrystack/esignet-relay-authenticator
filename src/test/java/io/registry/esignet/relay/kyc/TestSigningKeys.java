package io.registry.esignet.relay.kyc;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * TEST-ONLY helper. Generates an RSA-2048 keypair + a self-signed X.509 certificate using
 * BouncyCastle (test scope only) and loads them into an in-memory {@link KeyStore}, so signing tests
 * exercise {@link KycSigningKeyService} through its PRODUCTION keystore constructor. No keystore or
 * key is ever written to disk.
 */
public final class TestSigningKeys {

  /** Alias used inside the in-memory test keystore. */
  public static final String ALIAS = "kyc-signing";

  /** Password used for both the keystore and the key entry in tests. */
  public static final String PASSWORD = "test-pass";

  private TestSigningKeys() {}

  /** A generated keypair plus its self-signed certificate. */
  public record Bundle(KeyPair keyPair, X509Certificate certificate, KeyStore keyStore) {}

  /**
   * Generates a fresh RSA-2048 keypair, a 1-year self-signed certificate, and a PKCS12 keystore
   * containing them under {@link #ALIAS}.
   *
   * @return the generated bundle
   */
  public static Bundle generate() {
    return generate(2048);
  }

  /**
   * Generates a fresh RSA keypair of the given size, a 1-year self-signed certificate, and a PKCS12
   * keystore containing them under {@link #ALIAS}. Used to exercise the minimum-key-size guard.
   *
   * @param keySize the RSA modulus size in bits
   * @return the generated bundle
   */
  public static Bundle generate(int keySize) {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(keySize);
      KeyPair keyPair = generator.generateKeyPair();
      X509Certificate certificate = selfSign(keyPair);

      KeyStore keyStore = KeyStore.getInstance("PKCS12");
      keyStore.load(null, null);
      keyStore.setKeyEntry(
          ALIAS,
          keyPair.getPrivate(),
          PASSWORD.toCharArray(),
          new X509Certificate[] {certificate});

      return new Bundle(keyPair, certificate, keyStore);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to generate test signing keys", e);
    }
  }

  private static X509Certificate selfSign(KeyPair keyPair) throws Exception {
    Instant now = Instant.now();
    Date notBefore = Date.from(now.minus(1, ChronoUnit.HOURS));
    Date notAfter = Date.from(now.plus(365, ChronoUnit.DAYS));
    X500Principal subject = new X500Principal("CN=esignet-relay-authenticator-test");
    BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

    X509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            subject, serial, notBefore, notAfter, subject, keyPair.getPublic());
    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
    return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
  }
}
