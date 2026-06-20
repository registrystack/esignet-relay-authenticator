package io.registry.esignet.relay.kyc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.registry.esignet.relay.RelayAuthenticatorProperties;
import io.registry.esignet.relay.TestProperties;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * M6 unit tests for {@link ClaimMapper}: request planning (intersection filter, drops {@code $psut}
 * and {@code sub}, drops non-profile claims, empty when nothing overlaps) and response mapping
 * ({@code $psut}-&gt;sub, scalar type preservation, omits claims Relay did not return, sub always
 * present).
 */
class ClaimMapperTest {

  private static final String PSUT = "psut-abc-123";

  private RelayAuthenticatorProperties props;
  private ClaimMapper mapper;

  @BeforeEach
  void setUp() {
    props = TestProperties.valid();
    // Default claim-map (spec example) applies. Default profile claims from TestProperties are
    // individual_id, name, given_name, family_name, birthdate — so gender / address.region are
    // mapped but OUTSIDE the profile, exercising the intersection filter.
    mapper = new ClaimMapper(props);
  }

  // --- request planning ---

  @Test
  void relayClaimsForIntersectsAcceptedWithProfileAndDropsProtocolDerived() {
    // sub is protocol-derived; gender/address.region are mapped but not in the profile.
    List<String> accepted =
        List.of("sub", "individual_id", "name", "given_name", "gender", "address.region");

    List<String> planned = mapper.relayClaimsFor(accepted);

    assertEquals(List.of("individual_id", "name", "given_name"), planned,
        "must request only the accepted claims that the profile declares; drop sub/gender/region");
    assertFalse(planned.contains("sub"), "sub must never be requested from Relay");
    assertFalse(planned.contains("$psut"), "$psut sources must never be requested from Relay");
    assertFalse(planned.contains("gender"), "non-profile claim must be omitted");
    assertFalse(planned.contains("address.region"), "non-profile claim must be omitted");
  }

  @Test
  void relayClaimsForDropsSubMappedToPsut() {
    // sub maps to $psut in the default claim map; even listed explicitly it must be dropped.
    List<String> planned = mapper.relayClaimsFor(List.of("sub"));
    assertTrue(planned.isEmpty(), "sub ($psut) must never be requested from Relay");
  }

  @Test
  void relayClaimsForReturnsEmptyWhenNothingOverlaps() {
    // gender + address.region are mapped but not in the profile → nothing to request.
    List<String> planned = mapper.relayClaimsFor(List.of("gender", "address.region"));
    assertTrue(planned.isEmpty(), "result must be empty when no accepted claim is in the profile");
  }

  @Test
  void relayClaimsForReturnsEmptyForNullOrEmptyInput() {
    assertTrue(mapper.relayClaimsFor(null).isEmpty());
    assertTrue(mapper.relayClaimsFor(List.of()).isEmpty());
  }

  @Test
  void relayClaimsForDropsUnmappedClaims() {
    // "email" is not in the claim map at all.
    List<String> planned = mapper.relayClaimsFor(List.of("individual_id", "email"));
    assertEquals(List.of("individual_id"), planned, "unmapped claims are dropped");
  }

  @Test
  void relayClaimsForDeduplicatesAndIsStable() {
    List<String> planned =
        mapper.relayClaimsFor(List.of("name", "name", "individual_id", "name"));
    assertEquals(List.of("name", "individual_id"), planned,
        "result must be de-duplicated and preserve first-seen order");
  }

  // --- response mapping ---

  @Test
  void toUserInfoSetsSubFromPsutAndCopiesScalarsPreservingType() {
    Map<String, Object> released = new LinkedHashMap<>();
    released.put("individual_id", "NID-2001");
    released.put("name", "Maria Santos");
    released.put("birthdate", "1984-01-15");

    List<String> accepted = List.of("sub", "individual_id", "name", "birthdate");

    Map<String, Object> userInfo = mapper.toUserInfo(released, PSUT, accepted);

    assertEquals(PSUT, userInfo.get("sub"), "sub must be the PSUT");
    assertEquals("NID-2001", userInfo.get("individual_id"));
    assertEquals("Maria Santos", userInfo.get("name"));
    assertEquals("1984-01-15", userInfo.get("birthdate"));
  }

  @Test
  void toUserInfoPreservesNumberAndBooleanTypes() {
    // Build a dedicated mapper with number/boolean-bearing claims mapped + declared in the profile.
    RelayAuthenticatorProperties p = TestProperties.valid();
    Map<String, String> claimMap = new LinkedHashMap<>();
    claimMap.put("sub", "$psut");
    claimMap.put("age", "age");
    claimMap.put("verified", "verified");
    p.getEsignet().setClaimMap(claimMap);
    p.getRelay().setDefaultClaims(List.of("age", "verified"));
    ClaimMapper m = new ClaimMapper(p);

    Map<String, Object> released = new LinkedHashMap<>();
    released.put("age", 41);
    released.put("verified", Boolean.TRUE);

    Map<String, Object> userInfo = m.toUserInfo(released, PSUT, List.of("age", "verified", "sub"));

    assertInstanceOf(Integer.class, userInfo.get("age"), "number type must be preserved");
    assertEquals(41, userInfo.get("age"));
    assertInstanceOf(Boolean.class, userInfo.get("verified"), "boolean type must be preserved");
    assertEquals(Boolean.TRUE, userInfo.get("verified"));
    assertEquals(PSUT, userInfo.get("sub"));
  }

  @Test
  void toUserInfoOmitsClaimsRelayDidNotReturn() {
    Map<String, Object> released = new LinkedHashMap<>();
    released.put("individual_id", "NID-2001");
    // name/birthdate were accepted but NOT released by Relay.

    Map<String, Object> userInfo =
        mapper.toUserInfo(released, PSUT, List.of("individual_id", "name", "birthdate"));

    assertTrue(userInfo.containsKey("individual_id"));
    assertFalse(userInfo.containsKey("name"), "claim Relay did not return must be omitted");
    assertFalse(userInfo.containsKey("birthdate"), "claim Relay did not return must be omitted");
    assertEquals(PSUT, userInfo.get("sub"), "sub must still be present");
  }

  @Test
  void toUserInfoAlwaysIncludesSubEvenWhenNotAccepted() {
    Map<String, Object> released = new LinkedHashMap<>();
    released.put("individual_id", "NID-2001");

    // sub not in accepted list, and Relay never returns it.
    Map<String, Object> userInfo = mapper.toUserInfo(released, PSUT, List.of("individual_id"));

    assertEquals(PSUT, userInfo.get("sub"), "sub must always be present, derived from the PSUT");
  }

  @Test
  void toUserInfoWithNullReleasedClaimsStillIncludesSub() {
    Map<String, Object> userInfo = mapper.toUserInfo(null, PSUT, List.of("individual_id"));
    assertEquals(PSUT, userInfo.get("sub"));
    assertFalse(userInfo.containsKey("individual_id"));
  }
}
