package io.registry.esignet.relay.relay;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Typed result of a successful (200) attribute-release call.
 *
 * <p>Exposes the released {@code claims} as a {@code Map<String,Object>} preserving the scalar JSON
 * types Relay returned (strings, numbers, booleans, etc.), plus the profile metadata and the {@code
 * source} block. Callers must not log the claim values.
 */
public final class RelayReleaseResult {

  private final String profileId;
  private final String profileVersion;
  private final String purpose;
  private final Map<String, Object> claims;
  private final Map<String, Object> source;

  /**
   * @param profileId the profile id echoed by Relay
   * @param profileVersion the profile version echoed by Relay
   * @param purpose the purpose echoed by Relay
   * @param claims released claims, preserving scalar JSON types; may be empty, never {@code null}
   * @param source the {@code source} block; may be empty, never {@code null}
   */
  public RelayReleaseResult(
      String profileId,
      String profileVersion,
      String purpose,
      Map<String, Object> claims,
      Map<String, Object> source) {
    this.profileId = profileId;
    this.profileVersion = profileVersion;
    this.purpose = purpose;
    this.claims =
        claims == null
            ? Collections.emptyMap()
            : Collections.unmodifiableMap(new LinkedHashMap<>(claims));
    this.source =
        source == null
            ? Collections.emptyMap()
            : Collections.unmodifiableMap(new LinkedHashMap<>(source));
  }

  public String getProfileId() {
    return profileId;
  }

  public String getProfileVersion() {
    return profileVersion;
  }

  public String getPurpose() {
    return purpose;
  }

  /**
   * @return an immutable view of the released claims, preserving scalar JSON types
   */
  public Map<String, Object> getClaims() {
    return claims;
  }

  /**
   * @return an immutable view of the {@code source} block
   */
  public Map<String, Object> getSource() {
    return source;
  }

  /**
   * Redacted view. Reports claim NAMES and the source block only; never prints released claim VALUES.
   *
   * @return a log-safe description
   */
  @Override
  public String toString() {
    return "RelayReleaseResult{profileId="
        + profileId
        + ", profileVersion="
        + profileVersion
        + ", claimNames="
        + claims.keySet()
        + ", source="
        + source
        + "}";
  }
}
