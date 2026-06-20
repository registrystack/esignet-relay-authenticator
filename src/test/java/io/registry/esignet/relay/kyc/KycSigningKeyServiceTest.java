package io.registry.esignet.relay.kyc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.junit.jupiter.api.Test;

/**
 * M6 unit tests for {@link KycSigningKeyService}: deterministic kid (same key -&gt; same kid),
 * loading from an in-memory keystore through the production constructor, and exposing the RSA private
 * key + certificate + algorithm.
 */
class KycSigningKeyServiceTest {

  @Test
  void loadsRsaPrivateKeyAndCertificateFromInMemoryKeystore() {
    TestSigningKeys.Bundle bundle = TestSigningKeys.generate();

    KycSigningKeyService service =
        new KycSigningKeyService(
            bundle.keyStore(), TestSigningKeys.ALIAS, TestSigningKeys.PASSWORD, "RS256");

    assertNotNull(service.getPrivateKey());
    assertInstanceOf(RSAPrivateKey.class, service.getPrivateKey(), "private key must be RSA");
    assertEquals(bundle.certificate(), service.getCertificate(), "certificate must be the loaded one");
    assertEquals("RS256", service.getAlgorithm());
    assertNotNull(service.getKid());
    assertFalse(service.getKid().isBlank(), "kid must be set");
  }

  @Test
  void algorithmDefaultsToRs256WhenBlank() {
    TestSigningKeys.Bundle bundle = TestSigningKeys.generate();
    KycSigningKeyService service =
        new KycSigningKeyService(
            bundle.keyStore(), TestSigningKeys.ALIAS, TestSigningKeys.PASSWORD, "  ");
    assertEquals("RS256", service.getAlgorithm());
  }

  @Test
  void kidIsDeterministicForSameKey() {
    TestSigningKeys.Bundle bundle = TestSigningKeys.generate();

    KycSigningKeyService a =
        new KycSigningKeyService(
            bundle.keyStore(), TestSigningKeys.ALIAS, TestSigningKeys.PASSWORD, "RS256");
    KycSigningKeyService b =
        new KycSigningKeyService(
            bundle.keyStore(), TestSigningKeys.ALIAS, TestSigningKeys.PASSWORD, "RS256");

    assertEquals(a.getKid(), b.getKid(), "same key must always yield the same kid");

    // Recomputing directly from the public key gives the same value (stable scheme).
    String direct = KycSigningKeyService.computeKid((RSAPublicKey) bundle.certificate().getPublicKey());
    assertEquals(a.getKid(), direct, "kid must be the RFC 7638 thumbprint of the public key");
  }

  @Test
  void differentKeysYieldDifferentKids() {
    KycSigningKeyService a =
        signing(TestSigningKeys.generate());
    KycSigningKeyService b =
        signing(TestSigningKeys.generate());
    assertFalse(a.getKid().equals(b.getKid()), "different keys must yield different kids");
  }

  @Test
  void missingAliasFails() {
    TestSigningKeys.Bundle bundle = TestSigningKeys.generate();
    assertThrows(
        IllegalStateException.class,
        () ->
            new KycSigningKeyService(
                bundle.keyStore(), "no-such-alias", TestSigningKeys.PASSWORD, "RS256"));
  }

  @Test
  void rejectsRsaKeySmallerThanMinimum() {
    TestSigningKeys.Bundle weak = TestSigningKeys.generate(1024);
    assertThrows(
        IllegalStateException.class,
        () ->
            new KycSigningKeyService(
                weak.keyStore(), TestSigningKeys.ALIAS, TestSigningKeys.PASSWORD, "RS256"),
        "an RSA key below the minimum size must be rejected");
  }

  private static KycSigningKeyService signing(TestSigningKeys.Bundle bundle) {
    KeyStore ks = bundle.keyStore();
    return new KycSigningKeyService(ks, TestSigningKeys.ALIAS, TestSigningKeys.PASSWORD, "RS256");
  }
}
