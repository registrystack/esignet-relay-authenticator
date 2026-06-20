package io.registry.esignet.relay.kyc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.registry.esignet.relay.RelayAuthenticatorProperties;
import io.registry.esignet.relay.TestProperties;
import io.registry.esignet.relay.kyc.KycTokenException.Kind;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * M4 unit tests for {@link KycTokenService}.
 *
 * <p>Covers: token issue/verify round-trip, tampered token rejected (TOKEN_INVALID), expired token
 * rejected (TOKEN_EXPIRED), rp/client/txn mismatch rejected, PSUT determinism, PSUT cross-RP
 * difference, same-subject-different-rp gives different PSUT.
 */
class KycTokenServiceTest {

  private static final String SUBJECT = "NID-2001";
  private static final String SID_TYPE = "national_id";
  private static final String RP = "rp-test";
  private static final String CLIENT = "client-test";
  private static final String TXN = "txn-abc123";
  private static final List<String> AMR = List.of("OTP");

  private RelayAuthenticatorProperties props;
  private Clock fixedClock;
  private KycTokenService service;

  @BeforeEach
  void setUp() {
    props = TestProperties.valid();
    // Fixed clock at a stable point in time.
    fixedClock = Clock.fixed(Instant.ofEpochSecond(1_700_000_000L), ZoneOffset.UTC);
    service = new KycTokenService(props, new ObjectMapper(), fixedClock);
  }

  // --- construction ---

  @Test
  void constructionFailsWhenKycSecretBlank() {
    props.getEsignet().getKycToken().setHmacSecret("");
    assertThrows(IllegalStateException.class,
        () -> new KycTokenService(props, new ObjectMapper(), fixedClock));
  }

  @Test
  void constructionFailsWhenPsutSecretBlank() {
    props.getEsignet().getPsut().setHmacSecret("");
    assertThrows(IllegalStateException.class,
        () -> new KycTokenService(props, new ObjectMapper(), fixedClock));
  }

  // --- issue/verify round-trip ---

  @Test
  void issueAndVerifyRoundTripSucceeds() throws Exception {
    String token = service.issue(SUBJECT, SID_TYPE, RP, CLIENT, TXN, AMR);

    assertNotNull(token, "token must not be null");
    assertTrue(token.split("\\.", -1).length == 3, "token must have 3 parts");

    KycTokenClaims claims = service.verify(token, RP, CLIENT, TXN, SUBJECT);

    assertEquals(KycTokenService.ISSUER, claims.getIss());
    assertEquals(KycTokenService.AUDIENCE, claims.getAud());
    assertEquals(SUBJECT, claims.getSub());
    assertEquals(SID_TYPE, claims.getSid());
    assertEquals(RP, claims.getRp());
    assertEquals(CLIENT, claims.getClientId());
    assertEquals(TXN, claims.getTxn());
    assertEquals(AMR, claims.getAmr());
    assertNotNull(claims.getJti(), "jti must be set");
    assertTrue(claims.getExp() > claims.getIat(), "exp must be after iat");
    assertEquals(1_700_000_000L, claims.getIat());
    assertEquals(1_700_000_000L + props.getEsignet().getKycToken().getTtlSeconds(),
        claims.getExp());
  }

  @Test
  void verifySucceedsWithoutIndividualIdCheck() throws Exception {
    String token = service.issue(SUBJECT, SID_TYPE, RP, CLIENT, TXN, AMR);

    // null expectedIndividualId means skip the sub check
    KycTokenClaims claims = service.verify(token, RP, CLIENT, TXN, null);

    assertEquals(SUBJECT, claims.getSub());
  }

  @Test
  void eachTokenHasUniqueJti() throws Exception {
    String token1 = service.issue(SUBJECT, SID_TYPE, RP, CLIENT, TXN, AMR);
    String token2 = service.issue(SUBJECT, SID_TYPE, RP, CLIENT, TXN, AMR);

    KycTokenClaims claims1 = service.verify(token1, RP, CLIENT, TXN, SUBJECT);
    KycTokenClaims claims2 = service.verify(token2, RP, CLIENT, TXN, SUBJECT);

    assertNotEquals(claims1.getJti(), claims2.getJti(), "each token must have a unique jti");
  }

  // --- tampered token rejected ---

  @Test
  void tamperedSignatureRejectedAsTokenInvalid() {
    String token = service.issue(SUBJECT, SID_TYPE, RP, CLIENT, TXN, AMR);
    String tampered = token.substring(0, token.lastIndexOf('.') + 1) + "INVALIDSIG";

    KycTokenException ex =
        assertThrows(KycTokenException.class,
            () -> service.verify(tampered, RP, CLIENT, TXN, SUBJECT));

    assertEquals(Kind.TOKEN_INVALID, ex.getKind());
  }

  @Test
  void tamperedPayloadRejectedAsTokenInvalid() throws Exception {
    String token = service.issue(SUBJECT, SID_TYPE, RP, CLIENT, TXN, AMR);
    String[] parts = token.split("\\.", -1);

    // Modify sub in the payload
    String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
    String alteredJson = payloadJson.replace(SUBJECT, "HACKER-ID");
    String alteredPayload = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(alteredJson.getBytes());
    String tampered = parts[0] + "." + alteredPayload + "." + parts[2];

    KycTokenException ex =
        assertThrows(KycTokenException.class,
            () -> service.verify(tampered, RP, CLIENT, TXN, "HACKER-ID"));

    assertEquals(Kind.TOKEN_INVALID, ex.getKind());
  }

  @Test
  void nullTokenRejectedAsTokenInvalid() {
    KycTokenException ex =
        assertThrows(KycTokenException.class,
            () -> service.verify(null, RP, CLIENT, TXN, SUBJECT));
    assertEquals(Kind.TOKEN_INVALID, ex.getKind());
  }

  @Test
  void truncatedTokenRejectedAsTokenInvalid() {
    KycTokenException ex =
        assertThrows(KycTokenException.class,
            () -> service.verify("only.two", RP, CLIENT, TXN, SUBJECT));
    assertEquals(Kind.TOKEN_INVALID, ex.getKind());
  }

  @Test
  void garbageTokenRejectedAsTokenInvalid() {
    KycTokenException ex =
        assertThrows(KycTokenException.class,
            () -> service.verify("not.valid.jwt", RP, CLIENT, TXN, SUBJECT));
    assertEquals(Kind.TOKEN_INVALID, ex.getKind());
  }

  // --- expired token rejected ---

  @Test
  void expiredTokenRejectedAsTokenExpired() throws Exception {
    // Issue the token with the fixed clock.
    String token = service.issue(SUBJECT, SID_TYPE, RP, CLIENT, TXN, AMR);

    // Verify with a clock well past the TTL (300s by default → advance 400s).
    Clock futureClock = Clock.fixed(
        fixedClock.instant().plusSeconds(400), ZoneOffset.UTC);
    KycTokenService futureService = new KycTokenService(props, new ObjectMapper(), futureClock);

    KycTokenException ex =
        assertThrows(KycTokenException.class,
            () -> futureService.verify(token, RP, CLIENT, TXN, SUBJECT));

    assertEquals(Kind.TOKEN_EXPIRED, ex.getKind());
  }

  @Test
  void tokenAtExactExpiryBoundaryIsRejected() throws Exception {
    // exp = iat + 300; verify at exactly exp (not expired should be exp > now, i.e. at exp it's expired).
    String token = service.issue(SUBJECT, SID_TYPE, RP, CLIENT, TXN, AMR);

    // Advance exactly TTL seconds (so now == exp → rejected because exp <= now).
    int ttl = props.getEsignet().getKycToken().getTtlSeconds();
    Clock boundaryClk = Clock.fixed(fixedClock.instant().plusSeconds(ttl), ZoneOffset.UTC);
    KycTokenService boundaryService = new KycTokenService(props, new ObjectMapper(), boundaryClk);

    KycTokenException ex =
        assertThrows(KycTokenException.class,
            () -> boundaryService.verify(token, RP, CLIENT, TXN, SUBJECT));

    assertEquals(Kind.TOKEN_EXPIRED, ex.getKind());
  }

  // --- rp/client/txn mismatch rejected ---

  @Test
  void rpMismatchRejectedAsTokenInvalid() {
    String token = service.issue(SUBJECT, SID_TYPE, RP, CLIENT, TXN, AMR);

    KycTokenException ex =
        assertThrows(KycTokenException.class,
            () -> service.verify(token, "wrong-rp", CLIENT, TXN, SUBJECT));

    assertEquals(Kind.TOKEN_INVALID, ex.getKind());
  }

  @Test
  void clientMismatchRejectedAsTokenInvalid() {
    String token = service.issue(SUBJECT, SID_TYPE, RP, CLIENT, TXN, AMR);

    KycTokenException ex =
        assertThrows(KycTokenException.class,
            () -> service.verify(token, RP, "wrong-client", TXN, SUBJECT));

    assertEquals(Kind.TOKEN_INVALID, ex.getKind());
  }

  @Test
  void txnMismatchRejectedAsTokenInvalid() {
    String token = service.issue(SUBJECT, SID_TYPE, RP, CLIENT, TXN, AMR);

    KycTokenException ex =
        assertThrows(KycTokenException.class,
            () -> service.verify(token, RP, CLIENT, "wrong-txn", SUBJECT));

    assertEquals(Kind.TOKEN_INVALID, ex.getKind());
  }

  @Test
  void individualIdMismatchRejectedAsTokenInvalid() {
    String token = service.issue(SUBJECT, SID_TYPE, RP, CLIENT, TXN, AMR);

    KycTokenException ex =
        assertThrows(KycTokenException.class,
            () -> service.verify(token, RP, CLIENT, TXN, "WRONG-ID"));

    assertEquals(Kind.TOKEN_INVALID, ex.getKind());
  }

  // --- PSUT tests ---

  @Test
  void psutIsDeterministicForSameInputs() {
    String psut1 = service.derivePsut(RP, CLIENT, SID_TYPE, SUBJECT);
    String psut2 = service.derivePsut(RP, CLIENT, SID_TYPE, SUBJECT);

    assertEquals(psut1, psut2, "PSUT must be deterministic for the same inputs");
  }

  @Test
  void psutDiffersForDifferentRp() {
    String psut1 = service.derivePsut("rp-a", CLIENT, SID_TYPE, SUBJECT);
    String psut2 = service.derivePsut("rp-b", CLIENT, SID_TYPE, SUBJECT);

    assertNotEquals(psut1, psut2, "PSUT must differ across different RPs");
  }

  @Test
  void psutDiffersForDifferentClient() {
    String psut1 = service.derivePsut(RP, "client-a", SID_TYPE, SUBJECT);
    String psut2 = service.derivePsut(RP, "client-b", SID_TYPE, SUBJECT);

    assertNotEquals(psut1, psut2, "PSUT must differ across different clients");
  }

  @Test
  void psutDiffersForDifferentSubject() {
    String psut1 = service.derivePsut(RP, CLIENT, SID_TYPE, "NID-0001");
    String psut2 = service.derivePsut(RP, CLIENT, SID_TYPE, "NID-0002");

    assertNotEquals(psut1, psut2, "PSUT must differ for different subjects");
  }

  @Test
  void sameSubjectUnderDifferentRpYieldsDifferentPsut() {
    String psutForRpA = service.derivePsut("rp-a", CLIENT, SID_TYPE, SUBJECT);
    String psutForRpB = service.derivePsut("rp-b", CLIENT, SID_TYPE, SUBJECT);

    assertNotEquals(psutForRpA, psutForRpB,
        "same subject under different RP must yield different PSUT");
  }

  @Test
  void psutResistsDelimiterCollisionAcrossComponents() {
    // Under a naive "|"-join these two tuples would both serialize to "a|b|c|<subject>" and collide.
    // Component-wise base64url encoding must keep them distinct so the pairwise pseudonym holds.
    String psut1 = service.derivePsut("a|b", "c", SID_TYPE, SUBJECT);
    String psut2 = service.derivePsut("a", "b|c", SID_TYPE, SUBJECT);

    assertNotEquals(
        psut1, psut2, "PSUT must not collide when a '|' shifts across the rp/clientId boundary");
  }

  @Test
  void psutIsBase64UrlEncoded() {
    String psut = service.derivePsut(RP, CLIENT, SID_TYPE, SUBJECT);

    // Must be decodable as URL-safe base64 without padding.
    assertNotNull(psut);
    assertFalse(psut.isEmpty());
    // No standard base64 padding or '+'/'/'.
    assertFalse(psut.contains("="), "PSUT must have no padding");
    assertFalse(psut.contains("+"), "PSUT must use URL-safe alphabet");
    assertFalse(psut.contains("/"), "PSUT must use URL-safe alphabet");

    // Must be decodable.
    byte[] decoded = Base64.getUrlDecoder().decode(psut);
    assertEquals(32, decoded.length, "HMAC-SHA256 produces 32 bytes");
  }

  @Test
  void psutUsesSeperateSecretFromKycToken() {
    // Change one secret but not the other and verify PSUT changes but issued token structure
    // doesn't reveal PSUT secret.
    String psut1 = service.derivePsut(RP, CLIENT, SID_TYPE, SUBJECT);

    // Create a service with a different PSUT secret.
    RelayAuthenticatorProperties props2 = TestProperties.valid();
    props2.getEsignet().getPsut().setHmacSecret("different-psut-secret");
    KycTokenService service2 = new KycTokenService(props2, new ObjectMapper(), fixedClock);

    String psut2 = service2.derivePsut(RP, CLIENT, SID_TYPE, SUBJECT);

    assertNotEquals(psut1, psut2, "PSUT must change when the PSUT secret changes");

    // KYC tokens from the two services should NOT be cross-verifiable (different kyc secrets
    // would matter here, but we only changed psut secret, so kyc token should still verify).
    String token = service.issue(SUBJECT, SID_TYPE, RP, CLIENT, TXN, AMR);
    // Verify with service2 — it has the same KYC secret so must succeed.
    assertDoesNotThrow(() -> service2.verify(token, RP, CLIENT, TXN, SUBJECT));
  }

  @Test
  void kycTokenSecretAndPsutSecretAreIndependent() {
    // Change kyc secret → PSUT unchanged, but old token cannot be verified with new service.
    String psut1 = service.derivePsut(RP, CLIENT, SID_TYPE, SUBJECT);
    String token = service.issue(SUBJECT, SID_TYPE, RP, CLIENT, TXN, AMR);

    RelayAuthenticatorProperties props2 = TestProperties.valid();
    props2.getEsignet().getKycToken().setHmacSecret("different-kyc-secret");
    KycTokenService service2 = new KycTokenService(props2, new ObjectMapper(), fixedClock);

    String psut2 = service2.derivePsut(RP, CLIENT, SID_TYPE, SUBJECT);
    assertEquals(psut1, psut2, "PSUT must be unchanged when only KYC secret changes");

    // Token issued by service cannot be verified by service2 (different KYC secret).
    assertThrows(KycTokenException.class,
        () -> service2.verify(token, RP, CLIENT, TXN, SUBJECT));
  }

  // --- helper to assert no exception is thrown ---
  private static void assertDoesNotThrow(ThrowingRunnable r) {
    try {
      r.run();
    } catch (Exception e) {
      throw new AssertionError("Expected no exception but got: " + e, e);
    }
  }

  @FunctionalInterface
  interface ThrowingRunnable {
    void run() throws Exception;
  }
}
