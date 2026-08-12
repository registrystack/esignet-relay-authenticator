package io.registry.esignet.relay.kyc;

import io.registry.esignet.relay.RelayAuthenticatorProperties;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Maps between eSignet/OIDC UserInfo claims and Registry Relay source tokens, driven by the
 * configured {@code registry.esignet.claim-map.*} and {@code registry.relay.default-claims}.
 *
 * <p>Two pure, side-effect-free responsibilities:
 *
 * <ol>
 *   <li><b>Request planning</b> ({@link #relayClaimsFor}): turn the eSignet-accepted claim names
 *       into the exact, provisioned Relay property list to request. Protocol-derived claims
 *       (anything mapped to {@code $psut}, and {@code sub}) are dropped — they are populated locally,
 *       never requested. The result is intersected with the configured provisioned property set so
 *       Relay V2 {@code fields} can only narrow disclosure.
 *   <li><b>Response mapping</b> ({@link #toUserInfo}): turn Relay's released claim map plus the
 *       PSUT into the eSignet UserInfo claim map, preserving scalar JSON types and always supplying
 *       {@code sub} from the PSUT.
 * </ol>
 *
 * <p>This class holds no secrets and logs nothing; it never sees released VALUES during request
 * planning and never logs them during response mapping.
 */
public class ClaimMapper {

  /** Reserved source token marking a protocol-derived, plugin-populated claim (the PSUT). */
  static final String PSUT_SOURCE = "$psut";

  /** The protocol-required subject claim. Always supplied from the PSUT, never from Relay. */
  static final String SUB_CLAIM = "sub";

  private final Map<String, String> claimMap;
  private final Set<String> profileClaims;

  /**
   * @param properties validated plugin configuration (claim map + provisioned Relay properties)
   */
  public ClaimMapper(RelayAuthenticatorProperties properties) {
    Objects.requireNonNull(properties, "properties");
    Map<String, String> configured = properties.getEsignet().getClaimMap();
    this.claimMap =
        configured == null
            ? Collections.emptyMap()
            : Collections.unmodifiableMap(new LinkedHashMap<>(configured));
    // The set of claims the active Relay profile/config declares.
    List<String> declared = properties.getRelay().getDefaultClaims();
    this.profileClaims =
        declared == null
            ? Collections.emptySet()
            : Collections.unmodifiableSet(new LinkedHashSet<>(declared));
  }

  /**
   * Plans the Relay source claims to request for the given eSignet-accepted claims.
   *
   * <p>For each accepted claim it resolves the Relay source via the claim map, drops protocol-derived
   * entries ({@code sub} and any source equal to {@code $psut}), and keeps only provisioned Relay
   * properties. The result is stable-ordered and de-duplicated, and MAY be empty; callers then skip
   * Relay so no default field set can be released.
   *
   * @param esignetAcceptedClaims the claims eSignet accepted/consented (may be {@code null}/empty)
   * @return the de-duplicated, provisioned Relay property list (never {@code null})
   */
  public List<String> relayClaimsFor(Collection<String> esignetAcceptedClaims) {
    if (esignetAcceptedClaims == null || esignetAcceptedClaims.isEmpty()) {
      return Collections.emptyList();
    }
    Set<String> planned = new LinkedHashSet<>();
    for (String accepted : esignetAcceptedClaims) {
      if (accepted == null || SUB_CLAIM.equals(accepted)) {
        // sub is protocol-derived; never requested from Relay.
        continue;
      }
      String source = claimMap.get(accepted);
      if (source == null || PSUT_SOURCE.equals(source)) {
        // Unmapped claim, or a protocol-derived claim populated locally — do not request.
        continue;
      }
      // Provisioned-property filter: V2 fields may only narrow the selected access profile.
      if (profileClaims.contains(source)) {
        planned.add(source);
      }
    }
    return new ArrayList<>(planned);
  }

  /**
   * Maps Relay's released claims plus the PSUT into the eSignet UserInfo claim map.
   *
   * <p>For each accepted eSignet claim present in the claim map: if its source is {@code $psut} the
   * value is the supplied {@code psut} (this populates {@code sub}); otherwise the value is copied
   * from {@code relayReleasedClaims} by source name when present, preserving the original scalar JSON
   * type. Claims Relay did not return are omitted (never fabricated). {@code sub} is ALWAYS present,
   * set to the PSUT, even though it is never requested from Relay.
   *
   * @param relayReleasedClaims the claims Relay released (source-keyed; may be {@code null}/empty)
   * @param psut the partner-specific user token; becomes the {@code sub} value
   * @param esignetAcceptedClaims the claims eSignet accepted/consented (may be {@code null}/empty)
   * @return the eSignet UserInfo claim map, stable-ordered, with {@code sub} always present
   */
  public Map<String, Object> toUserInfo(
      Map<String, Object> relayReleasedClaims,
      String psut,
      Collection<String> esignetAcceptedClaims) {
    Map<String, Object> released =
        relayReleasedClaims == null ? Collections.emptyMap() : relayReleasedClaims;
    Map<String, Object> userInfo = new LinkedHashMap<>();

    if (esignetAcceptedClaims != null) {
      for (String accepted : esignetAcceptedClaims) {
        if (accepted == null || SUB_CLAIM.equals(accepted)) {
          // sub is handled below from the PSUT regardless of whether eSignet listed it.
          continue;
        }
        String source = claimMap.get(accepted);
        if (source == null) {
          continue;
        }
        if (PSUT_SOURCE.equals(source)) {
          userInfo.put(accepted, psut);
        } else if (released.containsKey(source)) {
          // Preserve the scalar JSON type Relay returned; do not stringify or re-synthesize.
          userInfo.put(accepted, released.get(source));
        }
        // else: Relay did not return it — omit, never fabricate.
      }
    }

    // sub is protocol-required and always derived from the PSUT.
    userInfo.put(SUB_CLAIM, psut);
    return userInfo;
  }
}
