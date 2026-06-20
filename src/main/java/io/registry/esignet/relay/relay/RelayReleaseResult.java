package io.registry.esignet.relay.relay;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Typed result of a successful (200) attribute-release call.
 *
 * <p>Exposes the released {@code claims} as a {@code Map<String,Object>} preserving the scalar JSON
 * types Relay returned (strings, numbers, booleans, etc.), plus the profile metadata and the
 * optional {@code source} block. Callers must not log the claim values.
 *
 * <p>The Relay success body is exactly {@code {"profile_id","profile_version","claims",
 * "source"?}} — there is <b>no</b> top-level {@code purpose} field, and {@code source} may be gated
 * off by the profile's {@code include_source_metadata} config, in which case {@link #getSource()}
 * returns {@code null} (see {@link #hasSource()}).
 */
public final class RelayReleaseResult {

  private final String profileId;
  private final String profileVersion;
  private final Map<String, Object> claims;
  private final Map<String, Object> source;

  /**
   * @param profileId the profile id echoed by Relay
   * @param profileVersion the profile version echoed by Relay
   * @param claims released claims, preserving scalar JSON types; may be empty, never {@code null}
   * @param source the optional {@code source} block; {@code null} when Relay omitted it (profile not
   *     configured to include source metadata)
   */
  public RelayReleaseResult(
      String profileId,
      String profileVersion,
      Map<String, Object> claims,
      Map<String, Object> source) {
    this.profileId = profileId;
    this.profileVersion = profileVersion;
    this.claims =
        claims == null
            ? Collections.emptyMap()
            : Collections.unmodifiableMap(new LinkedHashMap<>(claims));
    this.source =
        source == null ? null : Collections.unmodifiableMap(new LinkedHashMap<>(source));
  }

  public String getProfileId() {
    return profileId;
  }

  public String getProfileVersion() {
    return profileVersion;
  }

  /**
   * @return an immutable view of the released claims, preserving scalar JSON types
   */
  public Map<String, Object> getClaims() {
    return claims;
  }

  /**
   * @return an immutable view of the optional {@code source} block, or {@code null} when Relay did
   *     not include source metadata for this profile
   */
  public Map<String, Object> getSource() {
    return source;
  }

  /**
   * @return {@code true} when Relay included a {@code source} block, {@code false} when it was gated
   *     off by the profile
   */
  public boolean hasSource() {
    return source != null;
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
