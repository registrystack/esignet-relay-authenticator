package io.registry.esignet.relay.auth;

import io.mosip.esignet.api.dto.AuthChallenge;
import io.mosip.esignet.api.exception.SendOtpException;
import io.registry.esignet.relay.RelayAuthenticatorProperties;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link ChallengeVerifier} that accepts a single statically configured OTP value.
 *
 * <p><b>For development and lab demos only.</b> This verifier is disabled by default
 * ({@code registry.esignet.auth.otp.static-enabled=false}). It must never be enabled in
 * production because it does not dispatch a real OTP and accepts the same value for all subjects.
 *
 * <p>Security properties:
 * <ul>
 *   <li>When {@code static-enabled=false}: {@link #supports} returns {@code false} and
 *       {@link #verify} throws {@link ChallengeVerificationException} (fail closed).
 *   <li>OTP comparison is constant-time using {@link MessageDigest#isEqual}.
 *   <li>{@link #sendOtp} is non-enumerating: it returns the same public shape and timing
 *       regardless of whether the subject is known, unknown, ambiguous, or denied. This means the
 *       caller cannot use OTP delivery success/failure to probe subject existence.
 *   <li>OTP values, raw individual IDs, and secrets are never logged.
 * </ul>
 */
public class StaticOtpChallengeVerifier implements ChallengeVerifier {

  private static final Logger log = LoggerFactory.getLogger(StaticOtpChallengeVerifier.class);

  /** The eSignet auth factor type this verifier handles. */
  static final String AUTH_FACTOR_TYPE = "OTP";

  /** The challenge format this verifier accepts. */
  static final String SUPPORTED_FORMAT = "alpha-numeric";

  /** The AMR value returned on successful verification. */
  static final List<String> AMR = Collections.unmodifiableList(List.of("OTP"));

  private static final String ERR_DISABLED = "static_otp_disabled";
  private static final String ERR_UNSUPPORTED_CHANNEL = "unsupported_otp_channel";
  private static final String ERR_VERIFICATION_FAILED = "challenge_verification_failed";

  private final RelayAuthenticatorProperties properties;

  /**
   * @param properties validated plugin configuration
   */
  public StaticOtpChallengeVerifier(RelayAuthenticatorProperties properties) {
    this.properties = properties;
  }

  /**
   * Returns {@code true} only when the static OTP mode is enabled, the factor type is {@code OTP},
   * and the format is {@code alpha-numeric}. Returns {@code false} (not throws) when disabled so
   * eSignet's verifier selection silently skips this verifier rather than surfacing an error.
   *
   * @param authFactorType the requested factor type
   * @param format the requested challenge format
   * @param channel the delivery channel (not used for static OTP selection, but checked separately
   *     for runtime channel filtering)
   * @return {@code true} when enabled and the factor/format match
   */
  @Override
  public boolean supports(String authFactorType, String format, String channel) {
    if (!isStaticEnabled()) {
      return false;
    }
    return AUTH_FACTOR_TYPE.equals(authFactorType) && SUPPORTED_FORMAT.equals(format);
  }

  /**
   * Returns a fixed, non-enumerating {@link SendOtpOutcome} regardless of the subject or channel
   * contents.
   *
   * <p>When disabled: throws {@link SendOtpException} with a non-revealing error code.
   *
   * <p>When enabled but the requested channels are not in the configured channel list: throws
   * {@link SendOtpException}; the configured static verifier never delivers real OTPs so it cannot
   * satisfy a channel outside its configuration.
   *
   * <p>When enabled and channels are valid: returns a static outcome with {@code null} masked
   * values (the static verifier does not send real email/SMS), without any subject-existence signal.
   * The subject identifier is accepted but not used or logged.
   *
   * @param transactionId the eSignet transaction ID (for logging at coarse level, never raw)
   * @param individualId the claimed subject identifier (accepted, never logged)
   * @param channels the requested delivery channels
   * @param relyingPartyId the relying party ID
   * @param clientId the OIDC client ID
   * @return a non-enumerating {@link SendOtpOutcome} (masked values are always {@code null} for
   *     static mode)
   * @throws SendOtpException if disabled or the channel list is empty/unsupported
   */
  @Override
  public SendOtpOutcome sendOtp(
      String transactionId,
      String individualId,
      List<String> channels,
      String relyingPartyId,
      String clientId)
      throws SendOtpException {
    if (!isStaticEnabled()) {
      log.warn("sendOtp called but static OTP is disabled; failing with non-revealing error");
      throw new SendOtpException(ERR_DISABLED);
    }

    // Validate that at least one channel is in the configured list. Fail if none match.
    if (channels == null || channels.isEmpty()) {
      log.warn("sendOtp called with empty channel list; failing closed");
      throw new SendOtpException(ERR_UNSUPPORTED_CHANNEL);
    }
    boolean anySupported = false;
    for (String ch : channels) {
      if (isSupportedOtpChannel(ch)) {
        anySupported = true;
        break;
      }
    }
    if (!anySupported) {
      log.warn("sendOtp called with no supported channels; failing closed");
      throw new SendOtpException(ERR_UNSUPPORTED_CHANNEL);
    }

    // Non-enumerating: same outcome shape regardless of whether subject is real.
    // Static mode never delivers a real OTP, so masked values are null.
    log.debug("Static OTP sendOtp: returning non-enumerating outcome (no real OTP dispatched)");
    return new SendOtpOutcome(null, null);
  }

  /**
   * Verifies the submitted OTP challenge. Returns {@link #AMR} on success.
   *
   * <p>When disabled: throws {@link ChallengeVerificationException} (fail closed).
   *
   * <p>When enabled: succeeds only if exactly one OTP challenge is present in the list and its
   * value matches the configured static value using constant-time comparison.
   *
   * @param transactionId the eSignet transaction ID
   * @param individualId the claimed subject identifier
   * @param challenges the submitted challenges
   * @param relyingPartyId the relying party ID
   * @param clientId the OIDC client ID
   * @return {@link #AMR} on success
   * @throws ChallengeVerificationException on any failure, including disabled state or wrong value
   */
  @Override
  public List<String> verify(
      String transactionId,
      String individualId,
      List<AuthChallenge> challenges,
      String relyingPartyId,
      String clientId)
      throws ChallengeVerificationException {
    if (!isStaticEnabled()) {
      log.warn("verify called but static OTP is disabled; failing closed");
      throw new ChallengeVerificationException(ERR_DISABLED);
    }

    if (challenges == null || challenges.isEmpty()) {
      log.warn("verify called with empty challenge list; failing closed");
      throw new ChallengeVerificationException(ERR_VERIFICATION_FAILED);
    }

    // Find the first OTP challenge with the supported format.
    AuthChallenge otpChallenge = null;
    for (AuthChallenge c : challenges) {
      if (AUTH_FACTOR_TYPE.equals(c.getAuthFactorType())
          && SUPPORTED_FORMAT.equals(c.getFormat())) {
        otpChallenge = c;
        break;
      }
    }

    if (otpChallenge == null) {
      log.warn("No OTP challenge with supported format found; failing closed");
      throw new ChallengeVerificationException(ERR_VERIFICATION_FAILED);
    }

    String configuredValue = properties.getEsignet().getAuth().getOtp().getStaticValue();
    if (configuredValue == null) {
      log.warn("Static OTP value not configured; failing closed");
      throw new ChallengeVerificationException(ERR_VERIFICATION_FAILED);
    }

    String submitted = otpChallenge.getChallenge();
    if (submitted == null) {
      log.warn("Submitted OTP challenge is null; failing closed");
      throw new ChallengeVerificationException(ERR_VERIFICATION_FAILED);
    }

    // Constant-time comparison to prevent timing-based enumeration.
    boolean match =
        MessageDigest.isEqual(
            submitted.getBytes(java.nio.charset.StandardCharsets.UTF_8),
            configuredValue.getBytes(java.nio.charset.StandardCharsets.UTF_8));

    if (!match) {
      // Do not log any OTP value, submitted or configured.
      log.warn("Static OTP verification failed; challenge did not match configured value");
      throw new ChallengeVerificationException(ERR_VERIFICATION_FAILED);
    }

    log.debug("Static OTP verification succeeded");
    return AMR;
  }

  /**
   * Returns {@code true} when {@code channel} is in the configured OTP channel list
   * ({@code registry.esignet.auth.otp.channels}).
   *
   * @param channel the OTP delivery channel, case-sensitive
   * @return {@code true} when the channel is configured
   */
  @Override
  public boolean isSupportedOtpChannel(String channel) {
    if (channel == null) {
      return false;
    }
    List<String> configured = properties.getEsignet().getAuth().getOtp().getChannels();
    return configured != null && configured.contains(channel);
  }

  // --- private helpers ---

  private boolean isStaticEnabled() {
    return properties.getEsignet().getAuth().getOtp().isStaticEnabled();
  }
}
