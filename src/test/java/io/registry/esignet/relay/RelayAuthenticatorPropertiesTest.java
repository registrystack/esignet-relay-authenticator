package io.registry.esignet.relay;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** M1: typed configuration validation and secret redaction. */
class RelayAuthenticatorPropertiesTest {

  @Test
  void validConfigurationPassesValidation() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    assertDoesNotThrow(props::validate);
  }

  @Test
  void missingRelayBearerTokenFailsFast() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    props.getRelay().getAuth().setBearerToken(null);

    RelayAuthenticatorConfigException ex =
        assertThrows(RelayAuthenticatorConfigException.class, props::validate);
    assertTrue(
        ex.getProblems().stream().anyMatch(p -> p.contains("registry.relay.auth.bearer-token")),
        "should report the missing Relay bearer token");
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
  void pathTemplateMissingProfileIdRejected() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    props.getRelay().getAttributeRelease().setPathTemplate("/v1/releases/versions/{version}");

    RelayAuthenticatorConfigException ex =
        assertThrows(RelayAuthenticatorConfigException.class, props::validate);
    assertTrue(
        ex.getProblems().stream().anyMatch(p -> p.contains("{profile_id}")),
        "should require {profile_id} in the path template");
  }

  @Test
  void pathTemplateMissingVersionRejected() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    props.getRelay().getAttributeRelease().setPathTemplate("/v1/releases/{profile_id}/resolve");

    RelayAuthenticatorConfigException ex =
        assertThrows(RelayAuthenticatorConfigException.class, props::validate);
    assertTrue(
        ex.getProblems().stream().anyMatch(p -> p.contains("{version}")),
        "should require {version} in the path template");
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

    assertFalse(rendered.contains("relay-test-token"), "bearer token must be redacted");
    assertFalse(rendered.contains("kyc-token-secret-value"), "KYC-token secret must be redacted");
    assertFalse(rendered.contains("psut-secret-value"), "PSUT secret must be redacted");
    assertFalse(rendered.contains("keystore-pass"), "keystore password must be redacted");
    assertFalse(rendered.contains("key-pass"), "key password must be redacted");
    assertFalse(rendered.contains("111111"), "static OTP value must be redacted");
    assertTrue(rendered.contains(RelayAuthenticatorProperties.REDACTED), "should show redaction marker");
    // Non-secret fields remain visible for operability.
    assertTrue(rendered.contains("esignet-civil-userinfo"), "non-secret profile id should be shown");
  }

  @Test
  void multipleProblemsCollectedInOnePass() {
    RelayAuthenticatorProperties props = TestProperties.valid();
    props.getRelay().getAuth().setBearerToken(null);
    props.getEsignet().getKycToken().setHmacSecret(null);
    props.getEsignet().getPsut().setHmacSecret(null);

    RelayAuthenticatorConfigException ex =
        assertThrows(RelayAuthenticatorConfigException.class, props::validate);
    assertTrue(ex.getProblems().size() >= 3, "should collect every problem in a single pass");
  }
}
