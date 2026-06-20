package io.registry.esignet.relay;

import io.registry.esignet.relay.auth.ChallengeVerifier;
import io.registry.esignet.relay.auth.StaticOtpChallengeVerifier;
import io.registry.esignet.relay.kyc.KycTokenService;
import io.registry.esignet.relay.relay.RelayAttributeReleaseClient;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration that builds the {@link RelayAuthenticationService} collaborator graph from the
 * typed {@link RelayAuthenticatorProperties}.
 *
 * <p>The whole graph is gated by the same conditional property as the authenticator bean
 * ({@code mosip.esignet.integration.authenticator=RelayAuthenticationService}), so none of these
 * beans load in an eSignet deployment that selects a different authenticator. This does not affect
 * the M0 bean-loading test, which only inspects the {@link RelayAuthenticationService} annotation
 * reflectively and never starts a Spring context.
 *
 * <p>Each bean is {@link ConditionalOnMissingBean} so a deployment (or a test) can supply its own
 * implementation — most importantly a production {@link ChallengeVerifier} in place of the
 * lab-only {@link StaticOtpChallengeVerifier}.
 */
@Configuration
@ConditionalOnProperty(
    value = "mosip.esignet.integration.authenticator",
    havingValue = RelayAuthenticationService.BEAN_NAME)
public class RelayAuthenticatorConfiguration {

  /**
   * The default {@link ChallengeVerifier}: the lab-only static OTP verifier (disabled by default).
   * Production deployments override this by registering their own {@link ChallengeVerifier} bean.
   *
   * @param properties validated plugin configuration
   * @return the default challenge verifier
   */
  @Bean
  @ConditionalOnMissingBean(ChallengeVerifier.class)
  public ChallengeVerifier challengeVerifier(RelayAuthenticatorProperties properties) {
    return new StaticOtpChallengeVerifier(properties);
  }

  /**
   * The Relay attribute-release HTTP client.
   *
   * @param properties validated plugin configuration
   * @return the Relay client
   */
  @Bean
  @ConditionalOnMissingBean(RelayAttributeReleaseClient.class)
  public RelayAttributeReleaseClient relayAttributeReleaseClient(
      RelayAuthenticatorProperties properties) {
    return new RelayAttributeReleaseClient(properties);
  }

  /**
   * The internal KYC token issuer/verifier and PSUT deriver.
   *
   * @param properties validated plugin configuration
   * @return the KYC token service
   */
  @Bean
  @ConditionalOnMissingBean(KycTokenService.class)
  public KycTokenService kycTokenService(RelayAuthenticatorProperties properties) {
    return new KycTokenService(properties);
  }
}
