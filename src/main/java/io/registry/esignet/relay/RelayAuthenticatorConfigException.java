package io.registry.esignet.relay;

import java.util.Collections;
import java.util.List;

/**
 * Thrown at startup when the plugin configuration is missing or invalid.
 *
 * <p>Carries the full list of problems so an operator can correct them in a single pass. The message
 * never echoes a configured secret value; it only names the offending property keys.
 */
public class RelayAuthenticatorConfigException extends RuntimeException {

  private final List<String> problems;

  /**
   * @param problems human-readable descriptions of each configuration problem (property keys, never
   *     secret values)
   */
  public RelayAuthenticatorConfigException(List<String> problems) {
    super("Invalid Relay Authenticator configuration: " + String.join("; ", problems));
    this.problems = List.copyOf(problems);
  }

  /**
   * @return an immutable list of the individual configuration problems
   */
  public List<String> getProblems() {
    return Collections.unmodifiableList(problems);
  }
}
