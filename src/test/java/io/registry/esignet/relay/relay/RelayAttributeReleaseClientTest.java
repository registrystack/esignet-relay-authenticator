package io.registry.esignet.relay.relay;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.registry.esignet.relay.RelayAuthenticatorProperties;
import io.registry.esignet.relay.TestProperties;
import io.registry.esignet.relay.relay.RelayStubServer.CapturedRequest;
import io.registry.esignet.relay.relay.RelayStubServer.StubResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** M2: contract tests for the Relay attribute-release client against the JDK HttpServer stub. */
class RelayAttributeReleaseClientTest {

  private RelayStubServer stub;
  private RelayAuthenticatorProperties props;
  private RelayAttributeReleaseClient client;

  @BeforeEach
  void setUp() throws IOException {
    stub = new RelayStubServer();
    props = TestProperties.valid();
    props.getRelay().setBaseUrl(stub.baseUrl());
    props.getRelay().setConnectTimeoutMs(2000);
    props.getRelay().setReadTimeoutMs(1000);
    props.validate();
    client = new RelayAttributeReleaseClient(props);
  }

  @AfterEach
  void tearDown() {
    if (stub != null) {
      stub.close();
    }
  }

  @Test
  void happyPathReturnsMappedClaimsAndSource() throws Exception {
    stub.setNextResponse(StubResponse.json(200, RelayStubServer.SUCCESS_BODY));

    RelayReleaseResult result =
        client.release("NID-2001", List.of("individual_id", "name", "given_name"));

    assertEquals("esignet-civil-userinfo", result.getProfileId());
    assertEquals("v1", result.getProfileVersion());
    Map<String, Object> claims = result.getClaims();
    assertEquals("NID-2001", claims.get("individual_id"));
    assertEquals("Maria Santos", claims.get("name"));
    assertEquals("Maria", claims.get("given_name"));
    assertEquals("1984-01-15", claims.get("birthdate"));

    Map<String, Object> source = result.getSource();
    assertEquals("civil_registry", source.get("dataset"));
    assertEquals("civil_person_detail", source.get("entity"));
    assertEquals("one", source.get("cardinality"));
  }

  @Test
  void sendsCorrectHeadersAndPath() throws Exception {
    stub.setNextResponse(StubResponse.json(200, RelayStubServer.SUCCESS_BODY));

    client.release("NID-2001", List.of("individual_id"));

    CapturedRequest req = stub.lastRequest();
    assertEquals("POST", req.method);
    assertEquals(
        "/v1/attribute-releases/esignet-civil-userinfo/versions/v1/resolve", req.path);
    assertEquals("Bearer relay-test-token", req.headers.get("Authorization"));
    assertEquals(
        "https://demo.example.gov/purpose/esignet-identity-verification",
        req.headers.get("Data-Purpose"));
    assertEquals("application/json", req.headers.get("Accept"));
    assertEquals("application/json", req.headers.get("Content-Type"));
  }

  @Test
  void sendsExactClaimListAndSubjectInBody() throws Exception {
    stub.setNextResponse(StubResponse.json(200, RelayStubServer.SUCCESS_BODY));

    client.release("NID-2001", List.of("individual_id", "name"));

    String body = stub.lastRequest().body;
    assertTrue(body.contains("\"id_type\":\"national_id\""), "subject id_type in body");
    assertTrue(body.contains("\"value\":\"NID-2001\""), "subject value in body");
    assertTrue(body.contains("\"claims\":[\"individual_id\",\"name\"]"), "exact claim list in body");
    // The subject value must never appear in the URL/path.
    assertFalse(stub.lastRequest().path.contains("NID-2001"), "subject must not be in the URL");
  }

  @Test
  void successBodyHasNoPurposeAndIsNotRequired() throws Exception {
    // The real Relay success body carries no top-level `purpose`. Parsing must not require it.
    stub.setNextResponse(StubResponse.json(200, RelayStubServer.SUCCESS_BODY));

    RelayReleaseResult result = client.release("NID-2001", List.of("individual_id"));

    assertEquals("esignet-civil-userinfo", result.getProfileId());
    assertFalse(
        RelayStubServer.SUCCESS_BODY.contains("\"purpose\""),
        "stub success body must not include a top-level purpose field");
  }

  @Test
  void omitsClaimsFieldWhenNull() throws Exception {
    // null claims => omit the field entirely so Relay applies the profile default set.
    stub.setNextResponse(StubResponse.json(200, RelayStubServer.SUCCESS_BODY));

    client.release("NID-2001", null);

    String body = stub.lastRequest().body;
    assertFalse(body.contains("\"claims\""), "claims field must be omitted for null claims");
  }

  @Test
  void omitsClaimsFieldWhenEmpty() throws Exception {
    // An explicit empty `[]` is a 400 on Relay (deny_unknown_fields/strict). Empty => omit entirely.
    stub.setNextResponse(StubResponse.json(200, RelayStubServer.SUCCESS_BODY));

    client.release("NID-2001", List.of());

    String body = stub.lastRequest().body;
    assertFalse(body.contains("\"claims\""), "claims field must be omitted for an empty claim list");
    assertFalse(body.contains("[]"), "must never serialize an explicit empty claims array");
  }

  @Test
  void toleratesAbsentSourceBlock() throws Exception {
    // `source` may be gated off by the profile config; parsing must not NPE and source is optional.
    stub.setNextResponse(StubResponse.json(200, RelayStubServer.SUCCESS_BODY_NO_SOURCE));

    RelayReleaseResult result = client.release("NID-2001", List.of("individual_id"));

    assertEquals("esignet-civil-userinfo", result.getProfileId());
    assertEquals("NID-2001", result.getClaims().get("individual_id"));
    assertFalse(result.hasSource(), "source must be reported absent when Relay omits it");
    assertNull(result.getSource(), "absent source must be exposed as null, not an empty map");
  }

  // --- Distinguishable error codes: each maps to its own internal outcome ---

  @Test
  void profileNotFoundMapsToProfileNotFound() {
    assertErrorMapping(404, problem("release.profile_not_found"), RelayReleaseError.PROFILE_NOT_FOUND);
  }

  @Test
  void scopeDeniedMapsToScopeDenied() {
    assertErrorMapping(403, problem("auth.scope_denied"), RelayReleaseError.SCOPE_DENIED);
  }

  @Test
  void purposeRequiredMapsToPurposeRequired() {
    assertErrorMapping(400, problem("auth.purpose_required"), RelayReleaseError.PURPOSE_REQUIRED);
  }

  @Test
  void purposeDeniedMapsToPurposeDenied() {
    assertErrorMapping(403, problem("auth.purpose_denied"), RelayReleaseError.PURPOSE_DENIED);
  }

  @Test
  void subjectInvalidMapsToSubjectInvalid() {
    assertErrorMapping(400, problem("release.subject_invalid"), RelayReleaseError.SUBJECT_INVALID);
  }

  @Test
  void sourceUnavailableMapsToUnavailable() {
    // release.source_unavailable (503) collapses into the fail-closed UNAVAILABLE outcome.
    assertErrorMapping(503, problem("release.source_unavailable"), RelayReleaseError.UNAVAILABLE);
  }

  // --- Collapsed denial: identical body for every internal scenario -> SUBJECT_DENIED ---

  @Test
  void collapsedSubjectDeniedMapsToSubjectDeniedForEveryScenario() {
    // The stub returns the SAME body for all four internal scenarios. Drive each one and prove the
    // plugin produces one indistinguishable SUBJECT_DENIED with no sub-reason leaking out.
    String[] internalScenarios = {
      "subject-not-found", "subject-ambiguous", "release-condition-denied", "required-claim-missing"
    };
    for (String scenario : internalScenarios) {
      stub.setNextResponse(StubResponse.problem(403, RelayStubServer.SUBJECT_DENIED_BODY));
      RelayReleaseException ex =
          assertThrowsRelease(() -> client.release("NID-2001", List.of("individual_id")));
      assertEquals(
          RelayReleaseError.SUBJECT_DENIED,
          ex.getError(),
          "scenario " + scenario + " must collapse to SUBJECT_DENIED");
      assertEquals("release.subject_denied", ex.getWireCode());
      // No sub-reason should be present anywhere on the exception.
      assertFalse(
          String.valueOf(ex.getMessage()).contains(scenario),
          "the collapsed denial must not disclose the sub-reason");
    }
  }

  @Test
  void unknownCodeMapsToUnknown() {
    assertErrorMapping(418, problem("some.unmapped_code"), RelayReleaseError.UNKNOWN);
  }

  @Test
  void unparseableErrorBodyMapsToUnknown() {
    assertErrorMapping(500, "not json at all", RelayReleaseError.UNKNOWN);
  }

  // --- Transport read timeout -> UNAVAILABLE (fail closed) ---

  @Test
  void readTimeoutMapsToUnavailable() {
    // Stub delays beyond the 1000ms read timeout configured in setUp().
    stub.setNextResponse(new StubResponse(200, "application/json", RelayStubServer.SUCCESS_BODY, 3000));
    RelayReleaseException ex =
        assertThrowsRelease(() -> client.release("NID-2001", List.of("individual_id")));
    assertEquals(RelayReleaseError.UNAVAILABLE, ex.getError());
  }

  @Test
  void connectFailureMapsToUnavailable() {
    // Point at a closed port to force a transport failure.
    stub.close();
    RelayReleaseException ex =
        assertThrowsRelease(() -> client.release("NID-2001", List.of("individual_id")));
    assertEquals(RelayReleaseError.UNAVAILABLE, ex.getError());
  }

  // --- helpers ---

  private void assertErrorMapping(int status, String body, RelayReleaseError expected) {
    stub.setNextResponse(StubResponse.problem(status, body));
    RelayReleaseException ex =
        assertThrowsRelease(() -> client.release("NID-2001", List.of("individual_id")));
    assertEquals(expected, ex.getError(), "code-driven mapping, not status-driven");
  }

  private static String problem(String code) {
    return "{\"type\":\"https://registry-relay.dev/problems/x\",\"title\":\"t\",\"code\":\""
        + code
        + "\"}";
  }

  @FunctionalInterface
  private interface ReleaseCall {
    void run() throws RelayReleaseException;
  }

  private static RelayReleaseException assertThrowsRelease(ReleaseCall call) {
    try {
      call.run();
    } catch (RelayReleaseException e) {
      return e;
    }
    throw new AssertionError("expected RelayReleaseException");
  }
}
