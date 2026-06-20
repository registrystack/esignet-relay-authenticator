package io.registry.esignet.relay;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import io.mosip.esignet.api.dto.AuthChallenge;
import io.mosip.esignet.api.dto.KycAuthDto;
import io.mosip.esignet.api.dto.KycAuthResult;
import io.mosip.esignet.api.dto.SendOtpDto;
import io.mosip.esignet.api.dto.SendOtpResult;
import io.mosip.esignet.api.exception.KycAuthException;
import io.mosip.esignet.api.exception.SendOtpException;
import io.registry.esignet.relay.auth.ChallengeVerifier;
import io.registry.esignet.relay.auth.StaticOtpChallengeVerifier;
import io.registry.esignet.relay.kyc.KycTokenService;
import io.registry.esignet.relay.relay.RelayAttributeReleaseClient;
import io.registry.esignet.relay.relay.RelayStubServer;
import io.registry.esignet.relay.relay.RelayStubServer.StubResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * M5 tests for {@link RelayAuthenticationService#doKycAuth}, {@code sendOtp}, and
 * {@code isSupportedOtpChannel}, wired against the M2 {@link RelayStubServer}-backed Relay client and
 * an enabled {@link StaticOtpChallengeVerifier}.
 *
 * <p>The service's public collaborator constructor is the test seam: tests inject the stub-backed
 * client and test doubles directly without a Spring context.
 */
class RelayAuthenticationServiceKycAuthTest {

  private static final String RP = "test-rp";
  private static final String CLIENT = "test-client";
  private static final String TXN = "txn-123";
  private static final String INDIVIDUAL_ID = "NID-2001";
  private static final String OTP_VALUE = "111111";

  private RelayStubServer stub;
  private RelayAuthenticatorProperties props;
  private RelayAttributeReleaseClient relayClient;
  private ChallengeVerifier verifier;
  private KycTokenService kycTokenService;
  private RelayAuthenticationService service;

  @BeforeEach
  void setUp() throws IOException {
    stub = new RelayStubServer();
    props = TestProperties.valid();
    props.getRelay().setBaseUrl(stub.baseUrl());
    props.getRelay().setConnectTimeoutMs(2000);
    props.getRelay().setReadTimeoutMs(1000);
    props.getEsignet().getAuth().getOtp().setStaticEnabled(true); // enable the lab OTP verifier
    props.validate();

    relayClient = new RelayAttributeReleaseClient(props);
    verifier = new StaticOtpChallengeVerifier(props);
    kycTokenService = new KycTokenService(props);
    service = new RelayAuthenticationService(props, verifier, relayClient, kycTokenService);
  }

  @AfterEach
  void tearDown() {
    if (stub != null) {
      stub.close();
    }
  }

  // --- success ---

  @Test
  void successReturnsKycTokenAndPsutAndRequestsOnlyAccountCheckClaim() throws Exception {
    stub.setNextResponse(StubResponse.json(200, RelayStubServer.SUCCESS_BODY));

    KycAuthResult result = service.doKycAuth(RP, CLIENT, kycAuth(OTP_VALUE));

    assertNotNull(result.getKycToken(), "kycToken must be present");
    assertNotNull(result.getPartnerSpecificUserToken(), "psut must be present");

    // The KYC token must verify and bind to rp/client/txn/subject.
    assertNotNull(
        kycTokenService.verify(result.getKycToken(), RP, CLIENT, TXN, INDIVIDUAL_ID),
        "issued KYC token must verify");

    // PSUT must equal the deterministic derivation.
    assertEquals(
        kycTokenService.derivePsut(RP, CLIENT, "national_id", INDIVIDUAL_ID),
        result.getPartnerSpecificUserToken());

    // CRITICAL: Relay was asked ONLY for the account-check claim (no demographics before consent).
    assertEquals(1, stub.requests().size(), "exactly one Relay account-check call");
    String body = stub.lastRequest().body;
    assertTrue(
        body.contains("\"claims\":[\"individual_id\"]"),
        "account-check must request only [individual_id]");
    assertFalse(body.contains("\"name\""), "no demographic claim must be requested");
    assertFalse(body.contains("\"birthdate\""), "no demographic claim must be requested");
    assertFalse(stub.lastRequest().body.contains("\"given_name\""), "no demographics requested");
  }

  // --- wrong challenge: no Relay call ---

  @Test
  void wrongChallengeFailsChallengeAndDoesNotCallRelay() {
    stub.setNextResponse(StubResponse.json(200, RelayStubServer.SUCCESS_BODY));

    KycAuthException ex =
        assertThrows(KycAuthException.class, () -> service.doKycAuth(RP, CLIENT, kycAuth("999999")));

    assertEquals("relay_auth_challenge_failed", ex.getErrorCode());
    // Verify-before-Relay: the stub must have received NO request.
    assertTrue(stub.requests().isEmpty(), "Relay must NOT be called when the challenge fails");
  }

  @Test
  void disabledVerifierFailsChallengeAndDoesNotCallRelay() throws IOException {
    // Re-create with the static OTP verifier disabled (the production-default posture).
    props.getEsignet().getAuth().getOtp().setStaticEnabled(false);
    ChallengeVerifier disabled = new StaticOtpChallengeVerifier(props);
    service = new RelayAuthenticationService(props, disabled, relayClient, kycTokenService);
    stub.setNextResponse(StubResponse.json(200, RelayStubServer.SUCCESS_BODY));

    KycAuthException ex =
        assertThrows(KycAuthException.class, () -> service.doKycAuth(RP, CLIENT, kycAuth(OTP_VALUE)));

    assertEquals("relay_auth_challenge_failed", ex.getErrorCode());
    assertTrue(stub.requests().isEmpty(), "Relay must NOT be called when the verifier is disabled");
  }

  // --- collapsed subject denial: one generic failure ---

  @Test
  void collapsedSubjectDeniedMapsToGenericSubjectDenied() {
    stub.setNextResponse(StubResponse.problem(403, RelayStubServer.SUBJECT_DENIED_BODY));

    KycAuthException ex =
        assertThrows(KycAuthException.class, () -> service.doKycAuth(RP, CLIENT, kycAuth(OTP_VALUE)));

    assertEquals("relay_auth_subject_denied", ex.getErrorCode());
    // No sub-reason disclosed anywhere.
    String repr = String.valueOf(ex.getMessage()) + ex.getErrorCode();
    assertFalse(repr.contains("not_found"));
    assertFalse(repr.contains("ambiguous"));
  }

  // --- relay unavailable: fail closed ---

  @Test
  void sourceUnavailableMapsToRelayUnavailable() {
    stub.setNextResponse(
        StubResponse.problem(
            503, "{\"type\":\"x\",\"title\":\"t\",\"code\":\"release.source_unavailable\"}"));

    KycAuthException ex =
        assertThrows(KycAuthException.class, () -> service.doKycAuth(RP, CLIENT, kycAuth(OTP_VALUE)));

    assertEquals("relay_auth_relay_unavailable", ex.getErrorCode());
  }

  @Test
  void transportTimeoutMapsToRelayUnavailable() {
    // Delay beyond the 1000ms read timeout configured in setUp().
    stub.setNextResponse(new StubResponse(200, "application/json", RelayStubServer.SUCCESS_BODY, 3000));

    KycAuthException ex =
        assertThrows(KycAuthException.class, () -> service.doKycAuth(RP, CLIENT, kycAuth(OTP_VALUE)));

    assertEquals("relay_auth_relay_unavailable", ex.getErrorCode());
  }

  // --- distinguishable config error: scope denied ---

  @Test
  void scopeDeniedMapsToConfigError() {
    stub.setNextResponse(
        StubResponse.problem(403, "{\"type\":\"x\",\"title\":\"t\",\"code\":\"auth.scope_denied\"}"));

    KycAuthException ex =
        assertThrows(KycAuthException.class, () -> service.doKycAuth(RP, CLIENT, kycAuth(OTP_VALUE)));

    assertEquals("relay_config_scope_denied", ex.getErrorCode());
  }

  // --- input validation ---

  @Test
  void invalidInputMapsToInvalidRequestAndDoesNotCallRelay() {
    KycAuthDto noChallenge = new KycAuthDto();
    noChallenge.setTransactionId(TXN);
    noChallenge.setIndividualId(INDIVIDUAL_ID);
    noChallenge.setChallengeList(List.of());

    KycAuthException ex =
        assertThrows(KycAuthException.class, () -> service.doKycAuth(RP, CLIENT, noChallenge));

    assertEquals("relay_auth_invalid_request", ex.getErrorCode());
    assertTrue(stub.requests().isEmpty(), "Relay must NOT be called on invalid input");
  }

  @Test
  void blankRelyingPartyMapsToInvalidRequest() {
    KycAuthException ex =
        assertThrows(KycAuthException.class, () -> service.doKycAuth("", CLIENT, kycAuth(OTP_VALUE)));
    assertEquals("relay_auth_invalid_request", ex.getErrorCode());
  }

  // --- claimsMetadataRequired: names/structure only, no raw values ---

  @Test
  void claimsMetadataRequiredReturnsNamesOnlyNoRawValues() throws Exception {
    stub.setNextResponse(StubResponse.json(200, RelayStubServer.SUCCESS_BODY));

    KycAuthResult result = service.doKycAuth(RP, CLIENT, true, kycAuth(OTP_VALUE));

    Map<String, List<JsonNode>> metadata = result.getClaimsMetadata();
    assertNotNull(metadata, "claimsMetadata must be present when requested");
    assertTrue(metadata.containsKey("individual_id"), "must describe the account-check claim");

    // No raw released value (e.g. the demographic values from the stub) must appear in metadata.
    String repr = metadata.toString();
    assertFalse(repr.contains("Maria"), "metadata must not contain a raw given_name value");
    assertFalse(repr.contains("Santos"), "metadata must not contain a raw family_name value");
    assertFalse(repr.contains("1984-01-15"), "metadata must not contain a raw birthdate value");
    assertFalse(repr.contains("NID-2001"), "metadata must not contain a raw individual_id value");
  }

  // --- sendOtp: masked values, non-enumerating; isSupportedOtpChannel reflects config ---

  @Test
  void sendOtpReturnsMaskedValuesAndTransactionId() throws Exception {
    SendOtpResult result = service.sendOtp(RP, CLIENT, sendOtpDto(List.of("email")));

    assertEquals(TXN, result.getTransactionId());
    // The static verifier never dispatches a real OTP, so masked values are null (non-enumerating).
    // The important property is the call succeeds and reveals nothing about the subject.
    assertEquals(result.getMaskedEmail(), service.sendOtp(RP, CLIENT, sendOtpDto(List.of("email")))
        .getMaskedEmail());
  }

  @Test
  void sendOtpFailsForUnsupportedChannel() {
    assertThrows(
        SendOtpException.class, () -> service.sendOtp(RP, CLIENT, sendOtpDto(List.of("sms"))));
  }

  @Test
  void isSupportedOtpChannelReflectsConfiguredChannels() {
    assertTrue(service.isSupportedOtpChannel("email"));
    assertTrue(service.isSupportedOtpChannel("phone"));
    assertFalse(service.isSupportedOtpChannel("sms"));
    assertFalse(service.isSupportedOtpChannel(null));
  }

  // --- helpers ---

  private static KycAuthDto kycAuth(String otpValue) {
    AuthChallenge challenge = new AuthChallenge();
    challenge.setAuthFactorType("OTP");
    challenge.setFormat("alpha-numeric");
    challenge.setChallenge(otpValue);
    KycAuthDto dto = new KycAuthDto();
    dto.setTransactionId(TXN);
    dto.setIndividualId(INDIVIDUAL_ID);
    dto.setChallengeList(List.of(challenge));
    return dto;
  }

  private static SendOtpDto sendOtpDto(List<String> channels) {
    SendOtpDto dto = new SendOtpDto();
    dto.setTransactionId(TXN);
    dto.setIndividualId(INDIVIDUAL_ID);
    dto.setOtpChannels(channels);
    return dto;
  }
}
