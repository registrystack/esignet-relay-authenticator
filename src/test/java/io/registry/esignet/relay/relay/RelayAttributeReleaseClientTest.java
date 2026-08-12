package io.registry.esignet.relay.relay;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.registry.esignet.relay.RelayAuthenticatorProperties;
import io.registry.esignet.relay.TestProperties;
import io.registry.esignet.relay.relay.RelayStubServer.CapturedRequest;
import io.registry.esignet.relay.relay.RelayStubServer.StubResponse;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Wire-contract tests for Registry Mint authentication and the Relay V2 lookup. */
class RelayAttributeReleaseClientTest {

  private final ObjectMapper objectMapper = new ObjectMapper();
  private RelayStubServer stub;
  private RelayAuthenticatorProperties props;
  private RelayAttributeReleaseClient client;

  @BeforeEach
  void setUp() throws IOException {
    stub = new RelayStubServer();
    props = TestProperties.valid();
    props.getRelay().setBaseUrl(stub.baseUrl());
    props.getMint().setTokenEndpoint(stub.mintTokenEndpoint());
    props.getRelay().setReadTimeoutMs(1000);
    props.validate();
    client = new RelayAttributeReleaseClient(props);
  }

  @AfterEach
  void tearDown() {
    if (stub != null) stub.close();
  }

  @Test
  void sendsExactV2LookupAndParsesOnlyDomainData() throws Exception {
    RelayReleaseResult result =
        client.release("NID-2001", List.of("individual_id", "name", "given_name"));

    assertEquals("NID-2001", result.getClaims().get("individual_id"));
    assertEquals("Maria Santos", result.getClaims().get("name"));
    assertFalse(result.getClaims().containsKey("registryIdentifier"));
    assertFalse(result.getClaims().containsKey("accessProfile"));

    CapturedRequest request = stub.lastRequest();
    assertEquals("POST", request.method);
    assertEquals("/v2/resources/civil-person/lookups/by-uin", request.path);
    assertEquals("fields=individual_id,name,given_name&accessProfile=esignet", request.query);
    assertEquals("Bearer mint-issued-relay-token", request.headers.get("Authorization"));
    assertEquals("application/json", request.headers.get("Content-Type"));
    assertEquals("application/json", request.headers.get("Accept"));
    JsonNode requestBody = objectMapper.readTree(request.body);
    assertEquals(objectMapper.readTree("{\"selectors\":{\"uin\":\"NID-2001\"}}"), requestBody);
    assertEquals(1, requestBody.size(), "no V1 body members may remain");
  }

  @Test
  void mintRequestUsesExactAudienceClientIdentityKidAndFreshJti() throws Exception {
    client.release("NID-2001", List.of("individual_id"));
    CapturedRequest first = stub.mintRequests().get(0);
    assertEquals("/token", first.path, "must use Registry Mint's published token_endpoint path");
    assertEquals("application/x-www-form-urlencoded", first.headers.get("Content-Type"));
    Map<String, String> form = form(first.body);
    assertEquals("client_credentials", form.get("grant_type"));
    assertEquals(
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        form.get("client_assertion_type"));
    assertEquals(3, form.size(), "no scope or client secret may be sent");

    String firstAssertion = form.get("client_assertion");
    JsonNode header = segment(firstAssertion, 0);
    JsonNode claims = segment(firstAssertion, 1);
    assertEquals("RS256", header.path("alg").asText());
    assertEquals("mint-client-test-key", header.path("kid").asText());
    assertEquals("esignet-relay-authenticator", claims.path("iss").asText());
    assertEquals(claims.path("iss"), claims.path("sub"));
    assertEquals(
        stub.mintTokenEndpoint(),
        claims.path("aud").asText(),
        "assertion audience must exactly equal Mint's published /token endpoint");
    assertTrue(claims.path("exp").asLong() > claims.path("iat").asLong());
    assertTrue(claims.path("exp").asLong() - claims.path("iat").asLong() <= 300);
    assertFalse(claims.path("jti").asText().isBlank());

    client = new RelayAttributeReleaseClient(props);
    client.release("NID-2001", List.of("individual_id"));
    String secondAssertion = form(stub.mintRequests().get(1).body).get("client_assertion");
    assertNotEquals(segment(firstAssertion, 1).path("jti"), segment(secondAssertion, 1).path("jti"));
  }

  @Test
  void tokenIsCachedAcrossRelayCallsWithinLifetime() throws Exception {
    client.release("NID-2001", List.of("individual_id"));
    client.release("NID-2002", List.of("individual_id"));
    assertEquals(1, stub.mintRequests().size());
    assertEquals(2, stub.requests().size());
  }

  @Test
  void omitsAccessProfileOnlyWhenConfigurationDoesNotRequireIt() throws Exception {
    props.getRelay().setAccessProfile(null);
    client = new RelayAttributeReleaseClient(props);
    client.release("NID-2001", List.of("individual_id"));
    assertEquals("fields=individual_id", stub.lastRequest().query);
  }

  @Test
  void invalidSuccessEnvelopeFailsUnavailableAndReleasesNothing() {
    stub.setNextResponse(StubResponse.json(200, "{\"data\":{\"claims\":{\"name\":\"canary\"}}}"));
    RelayReleaseException failure =
        assertThrowsRelease(() -> client.release("NID-2001", List.of("name")));
    assertEquals(RelayReleaseError.UNAVAILABLE, failure.getError());
    assertEquals(null, failure.getCause(), "response parsing details must not escape as a cause");
    assertFalse(failure.getMessage().contains("canary"));
  }

  @Test
  void unresolvedConcealedAndDeniedCollapseToOneOutcomeIndependentOfStatus() {
    for (Map.Entry<Integer, String> caseValue :
        Map.of(
                404, "consultation.unresolved",
                403, "consultation.denied",
                401, "resource.not_found")
            .entrySet()) {
      stub.setNextResponse(StubResponse.problem(caseValue.getKey(), problem(caseValue.getValue())));
      RelayReleaseException failure =
          assertThrowsRelease(() -> client.release("NID-2001", List.of("individual_id")));
      assertEquals(RelayReleaseError.SUBJECT_DENIED, failure.getError());
    }
  }

  @Test
  void unavailableAndAuthenticationCodesAreRetryableWithoutMembershipDetail() {
    for (String code :
        List.of(
            "source.unavailable",
            "audit.unavailable",
            "service.not_ready",
            "internal.timeout",
            "auth.invalid_credential")) {
      stub.setNextResponse(StubResponse.problem(404, problem(code)));
      RelayReleaseException failure =
          assertThrowsRelease(() -> client.release("NID-2001", List.of("individual_id")));
      assertEquals(RelayReleaseError.UNAVAILABLE, failure.getError());
    }
  }

  @Test
  void authenticationFailureInvalidatesCachedToken() throws Exception {
    stub.setNextResponse(StubResponse.problem(401, problem("auth.invalid_credential")));
    assertThrowsRelease(() -> client.release("NID-2001", List.of("individual_id")));
    stub.setNextResponse(StubResponse.json(200, RelayStubServer.SUCCESS_BODY));
    client.release("NID-2001", List.of("individual_id"));
    assertEquals(2, stub.mintRequests().size());
  }

  @Test
  void mintFailureIsUnavailableAndRelayIsNotCalled() {
    stub.setNextMintResponse(StubResponse.problem(401, "{\"error\":\"invalid_client\"}"));
    RelayReleaseException failure =
        assertThrowsRelease(() -> client.release("NID-2001", List.of("individual_id")));
    assertEquals(RelayReleaseError.UNAVAILABLE, failure.getError());
    assertEquals(null, failure.getCause(), "Mint diagnostics must stay behind the boundary");
    assertTrue(stub.requests().isEmpty());
  }

  @Test
  void unknownProblemDoesNotUseHttpStatusAsMembershipSignal() {
    stub.setNextResponse(StubResponse.problem(404, problem("future.problem")));
    RelayReleaseException failure =
        assertThrowsRelease(() -> client.release("NID-2001", List.of("individual_id")));
    assertEquals(RelayReleaseError.UNAVAILABLE, failure.getError());
  }

  @Test
  void relayTimeoutIsUnavailable() {
    stub.setNextResponse(new StubResponse(200, "application/json", RelayStubServer.SUCCESS_BODY, 3000));
    RelayReleaseException failure =
        assertThrowsRelease(() -> client.release("NID-2001", List.of("individual_id")));
    assertEquals(RelayReleaseError.UNAVAILABLE, failure.getError());
  }

  private JsonNode segment(String jwt, int index) throws IOException {
    return objectMapper.readTree(Base64.getUrlDecoder().decode(jwt.split("\\.")[index]));
  }

  private static Map<String, String> form(String body) {
    Map<String, String> values = new HashMap<>();
    for (String pair : body.split("&")) {
      String[] parts = pair.split("=", 2);
      values.put(
          URLDecoder.decode(parts[0], StandardCharsets.UTF_8),
          URLDecoder.decode(parts[1], StandardCharsets.UTF_8));
    }
    return values;
  }

  private static String problem(String code) {
    return "{\"type\":\"x\",\"title\":\"t\",\"code\":\"" + code + "\"}";
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
