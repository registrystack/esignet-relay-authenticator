package io.registry.esignet.relay;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.registry.esignet.relay.auth.ChallengeVerifier;
import io.registry.esignet.relay.auth.StaticOtpChallengeVerifier;
import io.registry.esignet.relay.kyc.KycTokenService;
import io.registry.esignet.relay.relay.RelayAttributeReleaseClient;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

/**
 * M5: the collaborator graph is produced by {@link RelayAuthenticatorConfiguration} and gated by the
 * same conditional property as the authenticator bean.
 */
class RelayAuthenticatorConfigurationTest {

  @Test
  void gatedByStandardConditionalProperty() {
    ConditionalOnProperty condition =
        RelayAuthenticatorConfiguration.class.getAnnotation(ConditionalOnProperty.class);
    assertNotNull(condition, "configuration must be gated by @ConditionalOnProperty");
    assertTrue(
        condition.value().length == 1
            && "mosip.esignet.integration.authenticator".equals(condition.value()[0]),
        "must gate on the eSignet authenticator integration property");
    assertTrue(
        RelayAuthenticationService.BEAN_NAME.equals(condition.havingValue()),
        "havingValue must match the documented bean name so the whole graph loads together");
  }

  @Test
  void producesCollaboratorBeansFromProperties() {
    RelayAuthenticatorConfiguration config = new RelayAuthenticatorConfiguration();
    RelayAuthenticatorProperties props = TestProperties.valid();
    props.validate();

    ChallengeVerifier verifier = config.challengeVerifier(props);
    RelayAttributeReleaseClient client = config.relayAttributeReleaseClient(props);
    KycTokenService tokenService = config.kycTokenService(props);

    assertNotNull(verifier);
    assertTrue(
        verifier instanceof StaticOtpChallengeVerifier,
        "default verifier is the lab-only static OTP verifier");
    assertNotNull(client);
    assertNotNull(tokenService);
  }

  @Test
  void serviceConstructsFromCollaborators() {
    RelayAuthenticatorConfiguration config = new RelayAuthenticatorConfiguration();
    RelayAuthenticatorProperties props = TestProperties.valid();
    props.validate();

    RelayAuthenticationService service =
        new RelayAuthenticationService(
            props,
            config.challengeVerifier(props),
            config.relayAttributeReleaseClient(props),
            config.kycTokenService(props));

    assertNotNull(service);
  }
}
