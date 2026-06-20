package io.registry.esignet.relay.kyc;

/**
 * Thrown when the plugin cannot package the UserInfo/KYC payload in the form eSignet requested.
 *
 * <p>Carries a stable, machine-readable {@link #getCode() code} so the exchange layer can map it to
 * a fixed eSignet exchange error. The message must never include released claim values, key
 * material, or secrets.
 */
public class UserInfoPackagingException extends Exception {

  private final String code;

  /**
   * @param code a stable machine-readable error code
   * @param message a safe, non-identifying description
   */
  public UserInfoPackagingException(String code, String message) {
    super(message);
    this.code = code;
  }

  /**
   * @param code a stable machine-readable error code
   * @param message a safe, non-identifying description
   * @param cause the underlying cause
   */
  public UserInfoPackagingException(String code, String message, Throwable cause) {
    super(message, cause);
    this.code = code;
  }

  /**
   * @return the stable error code
   */
  public String getCode() {
    return code;
  }
}
