package io.registry.esignet.relay;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.esignet.api.dto.KycExchangeDto;
import io.mosip.esignet.api.dto.KycExchangeResult;
import io.mosip.esignet.api.dto.VerifiedKycExchangeDto;
import io.mosip.esignet.api.exception.KycExchangeException;
import io.registry.esignet.relay.auth.StaticOtpChallengeVerifier;
import io.registry.esignet.relay.kyc.ClaimMapper;
import io.registry.esignet.relay.kyc.KycSigningKeyService;
import io.registry.esignet.relay.kyc.KycTokenService;
import io.registry.esignet.relay.kyc.TestSigningKeys;
import io.registry.esignet.relay.kyc.UserInfoSigner;
import io.registry.esignet.relay.relay.RelayAttributeReleaseClient;
import io.registry.esignet.relay.relay.RelayStubServer;
import io.registry.esignet.relay.relay.RelayStubServer.StubResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * M7 tests for {@link RelayAuthenticationService#doKycExchange} and
 * {@link RelayAuthenticationService#doVerifiedKycExchange}, wired against the M2
 * {@link RelayStubServer}-backed Relay client, a real {@link KycTokenService} (so a real KYC token is
 * minted), a real {@link KycSigningKeyService} built from {@link TestSigningKeys} (so signing
 * actually produces a verifiable JWS), and a real {@link ClaimMapper}.
 *
 * <p>The service's 7-arg collaborator constructor is the test seam: tests inject the stub-backed
 * client and real collaborators directly without a Spring context.
 */
class RelayAuthenticationServiceKycExchangeTest {

  private static final String RP = "test-rp";
  private static final String CLIENT = "test-client";
  private static final String TXN = "txn-exchange-1";
  private static final String INDIVIDUAL_ID = "NID-2001";
  private static final String ID_TYPE = "national_id";

  private final ObjectMapper objectMapper = new ObjectMapper();

  private RelayStubServer stub;
  private RelayAuthenticatorProperties props;
  private RelayAttributeReleaseClient relayClient;
  private KycTokenService kycTokenService;
  private TestSigningKeys.Bundle bundle;
  private KycSigningKeyService signingKeyService;
  private UserInfoSigner userInfoSigner;
  private RelayAuthenticationService service;

  @BeforeEach
  void setUp() throws IOException {
    stub = new RelayStubServer();
    props = TestProperties.valid();
    props.getRelay().setBaseUrl(stub.baseUrl());
    props.getRelay().setConnectTimeoutMs(2000);
    props.getRelay().setReadTimeoutMs(1000);
    props.getEsignet().getAuth().getOtp().setStaticEnabled(true); // exchange never calls the verifier
    props.validate();

    relayClient = new RelayAttributeReleaseClient(props);
    kycTokenService = new KycTokenService(props);

    bundle = TestSigningKeys.generate();
    signingKeyService =
        new KycSigningKeyService(
            bundle.keyStore(), TestSigningKeys.ALIAS, TestSigningKeys.PASSWORD, "RS256");
    userInfoSigner = new UserInfoSigner(signingKeyService);

    service =
        new RelayAuthenticationService(
            props,
            new StaticOtpChallengeVerifier(props),
            relayClient,
            kycTokenService,
            new ClaimMapper(props),
            userInfoSigner,
            signingKeyService);
  }

  @AfterEach
  void tearDown() {
    if (stub != null) {
      stub.close();
    }
  }

  // --- happy path ---

  @Test
  void successRequestsConsentedClaimsSignsAndDerivesPsutSub() throws Exception {
    stub.setNextResponse(StubResponse.json(200, RelayStubServer.SUCCESS_BODY));
    String token = issueToken();

    // Accept a mix: sub (protocol-derived), profile claims, and gender (mapped but NOT in profile).
    KycExchangeDto dto =
        exchangeDto(token, List.of("sub", "individual_id", "name", "given_name", "gender"));

    KycExchangeResult result = service.doKycExchange(RP, CLIENT, dto);

    // (a) Relay was called with the profile-filtered intersection — no sub/$psut, no gender.
    assertEquals(1, stub.requests().size(), "exactly one Relay release call");
    String body = stub.lastRequest().body;
    assertTrue(
        body.contains("\"claims\":[\"individual_id\",\"name\",\"given_name\"]"),
        "Relay must be asked only for intersection(accepted, profile)");
    assertFalse(body.contains("\"sub\""), "sub must never be requested from Relay");
    assertFalse(body.contains("$psut"), "$psut must never be requested from Relay");
    assertFalse(body.contains("\"gender\""), "non-profile claim must be omitted");

    // (b) The returned encryptedKyc is a 3-part RS256 JWS that verifies against the signing cert.
    String jws = result.getEncryptedKyc();
    assertNotNull(jws, "exchange must return a serialized KYC payload");
    String[] parts = jws.split("\\.", -1);
    assertEquals(3, parts.length, "must be a 3-part compact JWS");

    String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
    assertTrue(headerJson.contains("\"alg\":\"RS256\""), "JWS alg must be RS256");
    assertTrue(
        headerJson.contains("\"kid\":\"" + signingKeyService.getKid() + "\""),
        "JWS header kid must equal the signing key kid");

    assertTrue(verifyJws(jws), "JWS signature must verify against the signing cert public key");

    // Decoded payload: mapped UserInfo with sub == derived PSUT and scalar types preserved.
    Map<String, Object> payload =
        objectMapper.readValue(
            Base64.getUrlDecoder().decode(parts[1]), new TypeReference<Map<String, Object>>() {});
    String expectedPsut = kycTokenService.derivePsut(RP, CLIENT, ID_TYPE, INDIVIDUAL_ID);
    assertEquals(expectedPsut, payload.get("sub"), "sub must equal the derived PSUT");
    assertEquals("NID-2001", payload.get("individual_id"));
    assertEquals("Maria", payload.get("given_name"));
    assertEquals("Maria Santos", payload.get("name"));
    assertInstanceOf(String.class, payload.get("name"), "scalar string type preserved");
    // gender was outside the profile, so it was never requested and never mapped.
    assertFalse(payload.containsKey("gender"), "non-profile claim must be absent from the payload");
  }

  // --- token expired: no Relay call ---

  @Test
  void expiredTokenMapsToTokenExpiredAndDoesNotCallRelay() {
    // A KycTokenService whose clock is far in the future so the freshly issued token has expired.
    KycTokenService future =
        new KycTokenService(
            props, new ObjectMapper(), java.time.Clock.fixed(
                java.time.Instant.now().plusSeconds(3600), java.time.ZoneOffset.UTC));
    RelayAuthenticationService futureService =
        new RelayAuthenticationService(
            props,
            new StaticOtpChallengeVerifier(props),
            relayClient,
            future,
            new ClaimMapper(props),
            userInfoSigner,
            signingKeyService);

    String token = issueToken(); // issued at "now", but futureService sees it as expired
    KycExchangeDto dto = exchangeDto(token, List.of("individual_id"));

    KycExchangeException ex =
        assertThrows(KycExchangeException.class, () -> futureService.doKycExchange(RP, CLIENT, dto));

    assertEquals("relay_auth_token_expired", ex.getErrorCode());
    assertTrue(stub.requests().isEmpty(), "Relay must NOT be called when the token is expired");
  }

  // --- token invalid: no Relay call ---

  @Test
  void tamperedTokenMapsToTokenInvalidAndDoesNotCallRelay() {
    String token = issueToken();
    String tampered = token.substring(0, token.length() - 2) + (token.endsWith("a") ? "b" : "a");
    KycExchangeDto dto = exchangeDto(tampered, List.of("individual_id"));

    KycExchangeException ex =
        assertThrows(KycExchangeException.class, () -> service.doKycExchange(RP, CLIENT, dto));

    assertEquals("relay_auth_token_invalid", ex.getErrorCode());
    assertTrue(stub.requests().isEmpty(), "Relay must NOT be called when the token is invalid");
  }

  @Test
  void wrongClientTokenMapsToTokenInvalidAndDoesNotCallRelay() {
    String token = issueToken();
    KycExchangeDto dto = exchangeDto(token, List.of("individual_id"));

    KycExchangeException ex =
        assertThrows(
            KycExchangeException.class, () -> service.doKycExchange(RP, "other-client", dto));

    assertEquals("relay_auth_token_invalid", ex.getErrorCode());
    assertTrue(stub.requests().isEmpty(), "Relay must NOT be called when the binding mismatches");
  }

  // --- JWE requested: fail closed BEFORE any release, no token ---

  @Test
  void jweRequestFailsClosedBeforeAnyReleaseWithNoToken() {
    stub.setNextResponse(StubResponse.json(200, RelayStubServer.SUCCESS_BODY));
    String token = issueToken();
    KycExchangeDto dto = exchangeDto(token, List.of("individual_id"));
    dto.setUserInfoResponseType("JWE");

    KycExchangeException ex =
        assertThrows(KycExchangeException.class, () -> service.doKycExchange(RP, CLIENT, dto));

    assertEquals("relay_kyc_jwe_unsupported", ex.getErrorCode());
    assertTrue(
        stub.requests().isEmpty(),
        "an unsupported JWE response must be rejected BEFORE any Relay release happens");
  }

  // --- no consented Relay claim remains: skip Relay, never release profile defaults ---

  @Test
  void noConsentedRelayClaimSkipsRelayAndReturnsOnlySub() throws Exception {
    // Accept only protocol-derived `sub` and a mapped-but-non-profile claim (gender). Both reduce out
    // of the Relay request, leaving an empty source list. The plugin must NOT call Relay — omitting
    // the claims field would make Relay release its profile DEFAULTS, an over-release nobody consented
    // to. A response is staged anyway to prove it is never consumed.
    stub.setNextResponse(StubResponse.json(200, RelayStubServer.SUCCESS_BODY));
    String token = issueToken();
    KycExchangeDto dto = exchangeDto(token, List.of("sub", "gender"));

    KycExchangeResult result = service.doKycExchange(RP, CLIENT, dto);

    assertTrue(
        stub.requests().isEmpty(),
        "Relay must NOT be called when no consented, profile-filtered claim remains");

    String jws = result.getEncryptedKyc();
    assertNotNull(jws, "must still return a signed payload carrying the protocol sub");
    assertTrue(verifyJws(jws), "JWS must verify against the signing cert");

    Map<String, Object> payload =
        objectMapper.readValue(
            Base64.getUrlDecoder().decode(jws.split("\\.")[1]),
            new TypeReference<Map<String, Object>>() {});
    String expectedPsut = kycTokenService.derivePsut(RP, CLIENT, ID_TYPE, INDIVIDUAL_ID);
    assertEquals(expectedPsut, payload.get("sub"), "sub must equal the derived PSUT");
    assertEquals(1, payload.size(), "only sub may be present — no profile defaults released");
    assertFalse(payload.containsKey("gender"), "a non-profile claim must never be released");
  }

  // --- Relay collapsed denial during exchange ---

  @Test
  void collapsedSubjectDeniedMapsToGenericSubjectDenied() {
    stub.setNextResponse(StubResponse.problem(403, RelayStubServer.SUBJECT_DENIED_BODY));
    String token = issueToken();
    KycExchangeDto dto = exchangeDto(token, List.of("individual_id", "name"));

    KycExchangeException ex =
        assertThrows(KycExchangeException.class, () -> service.doKycExchange(RP, CLIENT, dto));

    assertEquals("relay_auth_subject_denied", ex.getErrorCode());
    String repr = String.valueOf(ex.getMessage()) + ex.getErrorCode();
    assertFalse(repr.contains("not_found"), "no sub-reason must be disclosed");
    assertFalse(repr.contains("ambiguous"), "no sub-reason must be disclosed");
  }

  // --- Relay unavailable / timeout ---

  @Test
  void sourceUnavailableMapsToRelayUnavailable() {
    stub.setNextResponse(
        StubResponse.problem(
            503, "{\"type\":\"x\",\"title\":\"t\",\"code\":\"release.source_unavailable\"}"));
    String token = issueToken();
    KycExchangeDto dto = exchangeDto(token, List.of("individual_id"));

    KycExchangeException ex =
        assertThrows(KycExchangeException.class, () -> service.doKycExchange(RP, CLIENT, dto));

    assertEquals("relay_auth_relay_unavailable", ex.getErrorCode());
  }

  @Test
  void transportTimeoutMapsToRelayUnavailable() {
    // Delay beyond the 1000ms read timeout configured in setUp().
    stub.setNextResponse(
        new StubResponse(200, "application/json", RelayStubServer.SUCCESS_BODY, 3000));
    String token = issueToken();
    KycExchangeDto dto = exchangeDto(token, List.of("individual_id"));

    KycExchangeException ex =
        assertThrows(KycExchangeException.class, () -> service.doKycExchange(RP, CLIENT, dto));

    assertEquals("relay_auth_relay_unavailable", ex.getErrorCode());
  }

  // --- verified exchange equals standard exchange, no fabricated assurance ---

  @Test
  void verifiedExchangeReturnsSameSignedClaimsWithNoFabricatedAssurance() throws Exception {
    stub.setNextResponse(StubResponse.json(200, RelayStubServer.SUCCESS_BODY));
    String token = issueToken();

    VerifiedKycExchangeDto dto = new VerifiedKycExchangeDto();
    dto.setTransactionId(TXN);
    dto.setKycToken(token);
    dto.setIndividualId(INDIVIDUAL_ID);
    dto.setAcceptedClaims(List.of("sub", "individual_id", "name"));

    KycExchangeResult result = service.doVerifiedKycExchange(RP, CLIENT, dto);

    String jws = result.getEncryptedKyc();
    assertNotNull(jws, "verified exchange must return a serialized KYC payload");
    assertTrue(verifyJws(jws), "verified-exchange JWS must verify against the signing cert");

    Map<String, Object> payload =
        objectMapper.readValue(
            Base64.getUrlDecoder().decode(jws.split("\\.")[1]),
            new TypeReference<Map<String, Object>>() {});

    // Same claim values as a standard exchange for the same inputs.
    String expectedPsut = kycTokenService.derivePsut(RP, CLIENT, ID_TYPE, INDIVIDUAL_ID);
    assertEquals(expectedPsut, payload.get("sub"));
    assertEquals("NID-2001", payload.get("individual_id"));
    assertEquals("Maria Santos", payload.get("name"));

    // No fabricated assurance / verified-claims metadata.
    assertFalse(payload.containsKey("verification"), "must not fabricate a verification block");
    assertFalse(payload.containsKey("verified_claims"), "must not fabricate verified_claims");
  }

  // --- input validation ---

  @Test
  void blankTokenMapsToInvalidRequestAndDoesNotCallRelay() {
    KycExchangeDto dto = exchangeDto("", List.of("individual_id"));

    KycExchangeException ex =
        assertThrows(KycExchangeException.class, () -> service.doKycExchange(RP, CLIENT, dto));

    assertEquals("relay_auth_invalid_request", ex.getErrorCode());
    assertTrue(stub.requests().isEmpty(), "Relay must NOT be called on invalid input");
  }

  // --- helpers ---

  private String issueToken() {
    return kycTokenService.issue(INDIVIDUAL_ID, ID_TYPE, RP, CLIENT, TXN, List.of("OTP"));
  }

  private static KycExchangeDto exchangeDto(String token, List<String> acceptedClaims) {
    KycExchangeDto dto = new KycExchangeDto();
    dto.setTransactionId(TXN);
    dto.setKycToken(token);
    dto.setIndividualId(INDIVIDUAL_ID);
    dto.setAcceptedClaims(acceptedClaims);
    return dto;
  }

  /** Verifies a compact RS256 JWS signature against the test signing certificate's public key. */
  private boolean verifyJws(String jws) throws Exception {
    String[] parts = jws.split("\\.", -1);
    String signingInput = parts[0] + "." + parts[1];
    byte[] sig = Base64.getUrlDecoder().decode(parts[2]);
    Signature verifier = Signature.getInstance("SHA256withRSA");
    verifier.initVerify(bundle.certificate().getPublicKey());
    verifier.update(signingInput.getBytes(StandardCharsets.UTF_8));
    return verifier.verify(sig);
  }
}
