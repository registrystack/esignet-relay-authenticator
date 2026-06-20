package io.registry.esignet.relay.auth;

/**
 * Result of a {@link ChallengeVerifier#sendOtp} call carrying the masked delivery channel values
 * that may be returned to the eSignet caller.
 *
 * <p>Fields are {@code null} when the verifier is not configured to return that channel value (for
 * example, a static verifier that never dispatches a real message). Never populated with raw or
 * full values; masking is the verifier's responsibility.
 */
public final class SendOtpOutcome {

  private final String maskedEmail;
  private final String maskedMobile;

  /**
   * @param maskedEmail masked email address (may be {@code null} if not applicable/configured)
   * @param maskedMobile masked mobile number (may be {@code null} if not applicable/configured)
   */
  public SendOtpOutcome(String maskedEmail, String maskedMobile) {
    this.maskedEmail = maskedEmail;
    this.maskedMobile = maskedMobile;
  }

  /**
   * @return masked email address or {@code null}
   */
  public String getMaskedEmail() {
    return maskedEmail;
  }

  /**
   * @return masked mobile number or {@code null}
   */
  public String getMaskedMobile() {
    return maskedMobile;
  }

  /** Redacted view: never prints raw masking values (still partial-personal-data). */
  @Override
  public String toString() {
    return "SendOtpOutcome{maskedEmail="
        + (maskedEmail != null ? "[present]" : "null")
        + ", maskedMobile="
        + (maskedMobile != null ? "[present]" : "null")
        + "}";
  }
}
