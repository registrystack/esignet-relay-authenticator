package io.registry.esignet.relay.kyc;

/**
 * Thrown when KYC token verification fails. Carries a machine-readable {@link Kind} that
 * distinguishes expiry from other structural or binding failures so the caller can surface the
 * right eSignet error code.
 *
 * <p><b>Security:</b> the message must not include the raw token, signing secret, or any released
 * claim value.
 */
public class KycTokenException extends Exception {

  /** Distinguishes the reason the KYC token was rejected. */
  public enum Kind {
    /**
     * The token's {@code exp} claim is in the past. The token was once valid but has expired.
     * Map to an eSignet "session expired" or "token_expired" error.
     */
    TOKEN_EXPIRED,

    /**
     * The token is structurally invalid, has a bad signature, or its binding claims (rp, client,
     * txn, individualId) do not match the expected values. Map to an eSignet "token_invalid" error.
     */
    TOKEN_INVALID,
  }

  private final Kind kind;

  /**
   * @param kind the rejection reason
   * @param message a safe, non-identifying description
   */
  public KycTokenException(Kind kind, String message) {
    super(message);
    this.kind = kind;
  }

  /**
   * @param kind the rejection reason
   * @param message a safe, non-identifying description
   * @param cause the underlying cause
   */
  public KycTokenException(Kind kind, String message, Throwable cause) {
    super(message, cause);
    this.kind = kind;
  }

  /**
   * @return the rejection kind — {@link Kind#TOKEN_EXPIRED} or {@link Kind#TOKEN_INVALID}
   */
  public Kind getKind() {
    return kind;
  }
}
