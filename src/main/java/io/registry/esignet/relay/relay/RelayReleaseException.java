package io.registry.esignet.relay.relay;

/**
 * Typed, value-free failure of a Relay V2 lookup.
 */
public class RelayReleaseException extends Exception {

  private final RelayReleaseError error;
  /**
   * @param error the internal outcome, never {@code null}
   */
  public RelayReleaseException(RelayReleaseError error) {
    super("Relay lookup failed: " + error);
    this.error = error;
  }

  /**
   * @return the internal outcome to branch on
   */
  public RelayReleaseError getError() {
    return error;
  }
}
