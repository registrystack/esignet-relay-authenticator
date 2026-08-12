package io.registry.esignet.relay;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

/** M1: typed configuration validation and secret redaction. */
class RelayAuthenticatorPropertiesTest {

  @Test
  void validConfigurationPassesValidation() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    assertDoesNotThrow(props::validate);
  }

  @Test
  void missingMintPrivateJwkFailsFast() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    props.getMint().setPrivateJwk(null);

    RelayAuthenticatorConfigException ex =
        assertThrows(RelayAuthenticatorConfigException.class, props::validate);
    assertTrue(
        ex.getProblems().stream().anyMatch(p -> p.contains("registry.mint.private-jwk")),
        "should report the missing Mint private JWK");
  }

  @Test
  void missingKycTokenHmacSecretFailsFast() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    props.getEsignet().getKycToken().setHmacSecret("   ");

    RelayAuthenticatorConfigException ex =
        assertThrows(RelayAuthenticatorConfigException.class, props::validate);
    assertTrue(
        ex.getProblems().stream()
            .anyMatch(p -> p.contains("registry.esignet.kyc-token.hmac-secret")),
        "should report the missing KYC-token HMAC secret");
  }

  @Test
  void missingPsutHmacSecretFailsFast() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    props.getEsignet().getPsut().setHmacSecret(null);

    RelayAuthenticatorConfigException ex =
        assertThrows(RelayAuthenticatorConfigException.class, props::validate);
    assertTrue(
        ex.getProblems().stream().anyMatch(p -> p.contains("registry.esignet.psut.hmac-secret")),
        "should report the missing PSUT HMAC secret");
  }

  @Test
  void shortKycTokenHmacSecretRejected() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    props.getEsignet().getKycToken().setHmacSecret("too-short");

    RelayAuthenticatorConfigException ex =
        assertThrows(RelayAuthenticatorConfigException.class, props::validate);
    assertTrue(
        ex.getProblems().stream()
            .anyMatch(
                p ->
                    p.contains("registry.esignet.kyc-token.hmac-secret")
                        && p.contains("at least")),
        "should reject a non-blank but too-short KYC-token HMAC secret");
  }

  @Test
  void shortPsutHmacSecretRejected() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    props.getEsignet().getPsut().setHmacSecret("too-short");

    RelayAuthenticatorConfigException ex =
        assertThrows(RelayAuthenticatorConfigException.class, props::validate);
    assertTrue(
        ex.getProblems().stream()
            .anyMatch(
                p -> p.contains("registry.esignet.psut.hmac-secret") && p.contains("at least")),
        "should reject a non-blank but too-short PSUT HMAC secret");
  }

  @Test
  void missingRelayResourceFailsFast() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    props.getRelay().setResource(null);

    RelayAuthenticatorConfigException ex =
        assertThrows(RelayAuthenticatorConfigException.class, props::validate);
    assertTrue(
        ex.getProblems().stream()
            .anyMatch(p -> p.contains("registry.relay.resource")),
        "should require the Relay V2 resource");
  }

  @Test
  void missingRelayLookupFailsFast() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    props.getRelay().setLookup("   ");

    RelayAuthenticatorConfigException ex =
        assertThrows(RelayAuthenticatorConfigException.class, props::validate);
    assertTrue(
        ex.getProblems().stream()
            .anyMatch(p -> p.contains("registry.relay.lookup")),
        "should require the Relay V2 lookup");
  }

  @Test
  void identicalHmacSecretsRejected() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    // Both are long enough to pass the length floor; the point is that they are equal.
    String shared = "shared-hmac-secret-0123456789abcdef0123";
    props.getEsignet().getKycToken().setHmacSecret(shared);
    props.getEsignet().getPsut().setHmacSecret(shared);

    RelayAuthenticatorConfigException ex =
        assertThrows(RelayAuthenticatorConfigException.class, props::validate);
    assertTrue(
        ex.getProblems().stream().anyMatch(p -> p.contains("must differ")),
        "the KYC-token and PSUT HMAC secrets must be distinct");
  }

  @Test
  void gatedByStandardConditionalProperty() {
    // The properties bean must carry the same conditional gate as the authenticator, so it is never
    // created (and its fail-fast validation never runs) when a different authenticator is selected.
    ConditionalOnProperty condition =
        RelayAuthenticatorProperties.class.getAnnotation(ConditionalOnProperty.class);
    assertNotNull(condition, "properties must be gated by @ConditionalOnProperty to stay dormant");
    assertArrayEquals(
        new String[] {"mosip.esignet.integration.authenticator"},
        condition.value(),
        "must gate on the eSignet authenticator integration property");
    assertEquals(
        RelayAuthenticationService.BEAN_NAME,
        condition.havingValue(),
        "havingValue must match the bean name so validation only runs when this plugin is selected");
  }

  @Test
  void invalidBaseUrlRejected() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    props.getRelay().setBaseUrl("not-a-url");

    RelayAuthenticatorConfigException ex =
        assertThrows(RelayAuthenticatorConfigException.class, props::validate);
    assertTrue(
        ex.getProblems().stream().anyMatch(p -> p.contains("registry.relay.base-url")),
        "should reject a non-absolute base URL");
  }

  @Test
  void relativeBaseUrlRejected() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    props.getRelay().setBaseUrl("/relative/path");

    assertThrows(RelayAuthenticatorConfigException.class, props::validate);
  }

  @Test
  void invalidMintPrivateJwkRejected() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    props.getMint().setPrivateJwk("{\"kty\":\"oct\",\"k\":\"secret\"}");

    RelayAuthenticatorConfigException ex =
        assertThrows(RelayAuthenticatorConfigException.class, props::validate);
    assertTrue(ex.getProblems().stream().anyMatch(p -> p.contains("registry.mint.private-jwk")));
  }

  @Test
  void assertionLifetimeAboveMintBoundRejected() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    props.getMint().setAssertionLifetimeSeconds(301);

    RelayAuthenticatorConfigException ex =
        assertThrows(RelayAuthenticatorConfigException.class, props::validate);
    assertTrue(ex.getProblems().stream().anyMatch(p -> p.contains("assertion-lifetime-seconds")));
  }

  @Test
  void selfContainedJwsRequiresKeystoreSettings() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    props.getEsignet().getKyc().setResponseMode("self-contained-jws");
    props.getEsignet().getKyc().getSigning().setKeystorePath(null);
    props.getEsignet().getKyc().getSigning().setKeystorePassword(null);

    RelayAuthenticatorConfigException ex =
        assertThrows(RelayAuthenticatorConfigException.class, props::validate);
    assertTrue(
        ex.getProblems().stream()
            .anyMatch(p -> p.contains("registry.esignet.kyc.signing.keystore-path")),
        "should require keystore path for self-contained-jws");
    assertTrue(
        ex.getProblems().stream()
            .anyMatch(p -> p.contains("registry.esignet.kyc.signing.keystore-password")),
        "should require keystore password for self-contained-jws");
  }

  @Test
  void nonJwsResponseModeDoesNotRequireKeystore() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    props.getEsignet().getKyc().setResponseMode("plain");
    props.getEsignet().getKyc().getSigning().setKeystorePath(null);
    props.getEsignet().getKyc().getSigning().setKeystorePassword(null);
    props.getEsignet().getKyc().getSigning().setKeyAlias(null);
    props.getEsignet().getKyc().getSigning().setKeyPassword(null);

    assertDoesNotThrow(props::validate);
  }

  @Test
  void toStringRedactsAllSecrets() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    String rendered = props.toString();

    assertFalse(rendered.contains("\"d\":"), "Mint private JWK must be redacted");
    assertFalse(
        rendered.contains("kyc-token-hmac-secret-0123456789abcdef"),
        "KYC-token secret must be redacted");
    assertFalse(
        rendered.contains("psut-hmac-secret-0123456789abcdef0123"), "PSUT secret must be redacted");
    assertFalse(rendered.contains("keystore-pass"), "keystore password must be redacted");
    assertFalse(rendered.contains("key-pass"), "key password must be redacted");
    assertFalse(rendered.contains("111111"), "static OTP value must be redacted");
    assertTrue(rendered.contains(RelayAuthenticatorProperties.REDACTED), "should show redaction marker");
    // Non-secret fields remain visible for operability.
    assertTrue(rendered.contains("civil-person"), "non-secret Relay resource should be shown");
  }

  @Test
  void multipleProblemsCollectedInOnePass() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    props.getMint().setPrivateJwk(null);
    props.getEsignet().getKycToken().setHmacSecret(null);
    props.getEsignet().getPsut().setHmacSecret(null);

    RelayAuthenticatorConfigException ex =
        assertThrows(RelayAuthenticatorConfigException.class, props::validate);
    assertTrue(ex.getProblems().size() >= 3, "should collect every problem in a single pass");
  }
}
