package io.registry.esignet.relay.auth;

import io.mosip.esignet.api.dto.AuthChallenge;
import java.util.List;

/**
 * Abstraction for a component that can verify an authentication challenge submitted by an eSignet
 * user.
 *
 * <p>Implementations cover a specific factor type (OTP, PIN, biometric, etc.) and may handle
 * multiple formats or channels. The {@link #supports(String, String, String)} method lets the
 * caller select the right verifier at runtime.
 *
 * <p><b>Security contract:</b> implementations must be fail-closed (return {@code false} or throw
 * rather than pass when in doubt), constant-time for any secret comparison, and must never log raw
 * challenge values, individual IDs, or security secrets.
 */
public interface ChallengeVerifier {

  /**
   * Returns {@code true} if this verifier can handle the specified factor type, format, and channel
   * combination.
   *
   * @param authFactorType the factor type such as {@code "OTP"} or {@code "PIN"}
   * @param format the challenge format such as {@code "alpha-numeric"} or {@code "digits"}
   * @param channel the delivery channel such as {@code "email"} or {@code "phone"}; may be
   *     {@code null} if the factor has no delivery channel concept
   * @return {@code true} if this verifier handles the combination
   */
  boolean supports(String authFactorType, String format, String channel);

  /**
   * Initiates OTP delivery for the given subject. Must be non-enumerating: the returned result
   * shape must not reveal whether the subject is known, unknown, ambiguous, or denied. If the
   * verifier cannot deliver an OTP (static mode, channel not supported, etc.) it must return the
   * same public shape rather than a distinguishable error.
   *
   * <p>Implementations that do not support OTP delivery (non-OTP factors) may throw {@link
   * UnsupportedOperationException}.
   *
   * @param transactionId the eSignet transaction ID (for logging only, never logged raw)
   * @param individualId the subject identifier (never logged)
   * @param channels the requested OTP delivery channels
   * @param relyingPartyId the relying party ID
   * @param clientId the OIDC client ID
   * @return a {@link SendOtpOutcome} carrying masked channel values
   * @throws io.mosip.esignet.api.exception.SendOtpException if the channel is unsupported or the
   *     verifier is disabled
   */
  SendOtpOutcome sendOtp(
      String transactionId,
      String individualId,
      List<String> channels,
      String relyingPartyId,
      String clientId)
      throws io.mosip.esignet.api.exception.SendOtpException;

  /**
   * Verifies the submitted challenge list against the given context.
   *
   * @param transactionId the eSignet transaction ID
   * @param individualId the claimed subject identifier
   * @param challenges the submitted challenges (factor type, format, value)
   * @param relyingPartyId the relying party ID
   * @param clientId the OIDC client ID
   * @return the verified authentication methods/AMR values on success (for example {@code ["OTP"]})
   * @throws ChallengeVerificationException if the challenge is invalid, the verifier is disabled,
   *     or any other condition requires failing closed
   */
  List<String> verify(
      String transactionId,
      String individualId,
      List<AuthChallenge> challenges,
      String relyingPartyId,
      String clientId)
      throws ChallengeVerificationException;

  /**
   * Returns {@code true} if the given OTP channel is supported by this verifier's configuration.
   * Driven by the channel list from properties, not runtime state. Used by the service layer to
   * implement {@link io.mosip.esignet.api.spi.Authenticator#isSupportedOtpChannel(String)}.
   *
   * @param channel the channel name, case-sensitive
   * @return {@code true} when the channel is in the configured channel list
   */
  boolean isSupportedOtpChannel(String channel);
}
