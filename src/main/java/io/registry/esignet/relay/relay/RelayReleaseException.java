package io.registry.esignet.relay.relay;

/**
 * Typed failure of an attribute-release call, carrying the internal {@link RelayReleaseError}
 * outcome.
 *
 * <p>The message and the carried wire {@code code} are deliberately coarse: for {@link
 * RelayReleaseError#SUBJECT_DENIED} no sub-reason is ever present (Relay collapses them), and no Relay
 * response body, subject value, or bearer token is ever stored on this exception. Callers map this
 * to the appropriate eSignet exception in a later milestone.
 */
public class RelayReleaseException extends Exception {

  private final RelayReleaseError error;
  private final String wireCode;

  /**
   * @param error the internal outcome, never {@code null}
   */
  public RelayReleaseException(RelayReleaseError error) {
    this(error, error == null ? null : error.wireCode(), null);
  }

  /**
   * @param error the internal outcome, never {@code null}
   * @param wireCode the Relay RFC 9457 {@code code} actually observed, or {@code null} for transport
   *     errors
   * @param cause the underlying cause (for example an {@link java.io.IOException}), or {@code null}
   */
  public RelayReleaseException(RelayReleaseError error, String wireCode, Throwable cause) {
    super("Relay attribute release failed: " + error, cause);
    this.error = error;
    this.wireCode = wireCode;
  }

  /**
   * @return the internal outcome to branch on
   */
  public RelayReleaseError getError() {
    return error;
  }

  /**
   * @return the observed Relay {@code code}, or {@code null} for transport-level failures
   */
  public String getWireCode() {
    return wireCode;
  }
}
