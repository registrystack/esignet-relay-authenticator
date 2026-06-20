package io.registry.esignet.relay.auth;

/**
 * Thrown by {@link ChallengeVerifier#verify} when the challenge cannot be verified and the caller
 * must treat the authentication attempt as failed.
 *
 * <p>Implementations must fail closed: any ambiguous or missing information results in this
 * exception, never a successful outcome.
 *
 * <p><b>Security:</b> the message must not include raw challenge values, individual IDs, or
 * information that could help an attacker distinguish rejection reasons.
 */
public class ChallengeVerificationException extends Exception {

  /**
   * @param message a safe, non-identifying description of why verification failed
   */
  public ChallengeVerificationException(String message) {
    super(message);
  }

  /**
   * @param message a safe, non-identifying description of why verification failed
   * @param cause the underlying cause
   */
  public ChallengeVerificationException(String message, Throwable cause) {
    super(message, cause);
  }
}
