package io.registry.esignet.relay.relay;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** Immutable projection parsed only from Relay V2 {@code data.domainData}. */
public final class RelayReleaseResult {
  private final Map<String, Object> claims;

  public RelayReleaseResult(Map<String, Object> claims) {
    this.claims =
        claims == null
            ? Collections.emptyMap()
            : Collections.unmodifiableMap(new LinkedHashMap<>(claims));
  }

  public Map<String, Object> getClaims() {
    return claims;
  }

  @Override
  public String toString() {
    return "RelayReleaseResult{claimNames=" + claims.keySet() + "}";
  }
}
