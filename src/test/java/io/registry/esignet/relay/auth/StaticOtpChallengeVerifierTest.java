package io.registry.esignet.relay.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.mosip.esignet.api.dto.AuthChallenge;
import io.mosip.esignet.api.exception.SendOtpException;
import io.registry.esignet.relay.RelayAuthenticatorProperties;
import io.registry.esignet.relay.TestProperties;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * M3 unit tests for {@link StaticOtpChallengeVerifier}.
 *
 * <p>Covers: disabled-by-default, explicit-enable success, wrong OTP rejected, unsupported channel,
 * non-enumerating sendOtp, and asserts no OTP value appears in produced message strings.
 */
class StaticOtpChallengeVerifierTest {

  private static final String STATIC_VALUE = "111111";
  private static final String INDIVIDUAL_ID = "NID-2001";
  private static final String TXN = "txn-abc";
  private static final String RP = "test-rp";
  private static final String CLIENT = "test-client";

  private RelayAuthenticatorProperties props;

  @BeforeEach
  void setUp() {
    props = TestProperties.valid();
    // TestProperties sets staticEnabled=false and staticValue=111111 and channels=[email,phone].
  }

  // --- disabled-by-default ---

  @Test
  void supportsReturnsFalseWhenDisabled() {
    assertFalse(props.getEsignet().getAuth().getOtp().isStaticEnabled(),
        "static OTP must be disabled by default");
    StaticOtpChallengeVerifier verifier = new StaticOtpChallengeVerifier(props);

    assertFalse(verifier.supports("OTP", "alpha-numeric", "email"),
        "supports() must return false when disabled");
    assertFalse(verifier.supports("OTP", "alpha-numeric", null),
        "supports() must return false when disabled (null channel)");
  }

  @Test
  void verifyThrowsWhenDisabled() {
    StaticOtpChallengeVerifier verifier = new StaticOtpChallengeVerifier(props);

    ChallengeVerificationException ex =
        assertThrows(
            ChallengeVerificationException.class,
            () ->
                verifier.verify(
                    TXN,
                    INDIVIDUAL_ID,
                    List.of(otpChallenge(STATIC_VALUE)),
                    RP,
                    CLIENT));

    assertNotNull(ex.getMessage());
    // Must not reveal the OTP value in the exception message.
    assertFalse(
        ex.getMessage().contains(STATIC_VALUE),
        "exception message must not contain OTP value");
    assertFalse(
        ex.getMessage().contains(INDIVIDUAL_ID),
        "exception message must not contain individual ID");
  }

  @Test
  void sendOtpThrowsWhenDisabled() {
    StaticOtpChallengeVerifier verifier = new StaticOtpChallengeVerifier(props);

    SendOtpException ex =
        assertThrows(
            SendOtpException.class,
            () -> verifier.sendOtp(TXN, INDIVIDUAL_ID, List.of("email"), RP, CLIENT));

    assertNotNull(ex.getMessage());
    assertFalse(
        ex.getMessage().contains(INDIVIDUAL_ID),
        "exception message must not contain individual ID");
  }

  // --- explicit enable: success path ---

  @Test
  void supportsReturnsTrueWhenEnabledForOtp() {
    enableStatic();
    StaticOtpChallengeVerifier verifier = new StaticOtpChallengeVerifier(props);

    assertTrue(verifier.supports("OTP", "alpha-numeric", "email"));
    assertTrue(verifier.supports("OTP", "alpha-numeric", "phone"));
  }

  @Test
  void supportsReturnsFalseForWrongFactorType() {
    enableStatic();
    StaticOtpChallengeVerifier verifier = new StaticOtpChallengeVerifier(props);

    assertFalse(verifier.supports("PIN", "alpha-numeric", "email"));
    assertFalse(verifier.supports("BIO", "FINGER", null));
  }

  @Test
  void supportsReturnsFalseForWrongFormat() {
    enableStatic();
    StaticOtpChallengeVerifier verifier = new StaticOtpChallengeVerifier(props);

    assertFalse(verifier.supports("OTP", "numeric", "email"));
    assertFalse(verifier.supports("OTP", null, "email"));
  }

  @Test
  void verifySucceedsWithCorrectOtp() throws Exception {
    enableStatic();
    StaticOtpChallengeVerifier verifier = new StaticOtpChallengeVerifier(props);

    List<String> amr =
        verifier.verify(
            TXN, INDIVIDUAL_ID, List.of(otpChallenge(STATIC_VALUE)), RP, CLIENT);

    assertEquals(List.of("OTP"), amr);
  }

  @Test
  void verifySucceedsRegardlessOfIndividualId() throws Exception {
    // The static verifier doesn't validate that the individual ID exists; it just accepts the OTP.
    enableStatic();
    StaticOtpChallengeVerifier verifier = new StaticOtpChallengeVerifier(props);

    List<String> amr =
        verifier.verify(
            TXN, "unknown-subject-id", List.of(otpChallenge(STATIC_VALUE)), RP, CLIENT);

    assertEquals(List.of("OTP"), amr);
  }

  // --- wrong OTP rejected ---

  @Test
  void verifyRejectsWrongOtp() {
    enableStatic();
    StaticOtpChallengeVerifier verifier = new StaticOtpChallengeVerifier(props);

    ChallengeVerificationException ex =
        assertThrows(
            ChallengeVerificationException.class,
            () ->
                verifier.verify(
                    TXN, INDIVIDUAL_ID, List.of(otpChallenge("999999")), RP, CLIENT));

    assertNotNull(ex.getMessage());
    // Must NOT expose the wrong value or the correct value in the message.
    assertFalse(ex.getMessage().contains("999999"), "must not expose submitted OTP");
    assertFalse(ex.getMessage().contains(STATIC_VALUE), "must not expose configured OTP");
    assertFalse(
        ex.getMessage().contains(INDIVIDUAL_ID),
        "must not expose individual ID");
  }

  @Test
  void verifyRejectsNullChallenge() {
    enableStatic();
    StaticOtpChallengeVerifier verifier = new StaticOtpChallengeVerifier(props);

    AuthChallenge nullValueChallenge = new AuthChallenge();
    nullValueChallenge.setAuthFactorType("OTP");
    nullValueChallenge.setFormat("alpha-numeric");
    // challenge value not set → null

    assertThrows(
        ChallengeVerificationException.class,
        () -> verifier.verify(TXN, INDIVIDUAL_ID, List.of(nullValueChallenge), RP, CLIENT));
  }

  @Test
  void verifyRejectsWrongFactorTypeInChallengeList() {
    enableStatic();
    StaticOtpChallengeVerifier verifier = new StaticOtpChallengeVerifier(props);

    AuthChallenge pinChallenge = new AuthChallenge();
    pinChallenge.setAuthFactorType("PIN");
    pinChallenge.setFormat("alpha-numeric");
    pinChallenge.setChallenge(STATIC_VALUE);

    assertThrows(
        ChallengeVerificationException.class,
        () -> verifier.verify(TXN, INDIVIDUAL_ID, List.of(pinChallenge), RP, CLIENT));
  }

  @Test
  void verifyRejectsEmptyChallengeList() {
    enableStatic();
    StaticOtpChallengeVerifier verifier = new StaticOtpChallengeVerifier(props);

    assertThrows(
        ChallengeVerificationException.class,
        () -> verifier.verify(TXN, INDIVIDUAL_ID, List.of(), RP, CLIENT));
  }

  // --- unsupported channel ---

  @Test
  void sendOtpFailsForUnsupportedChannel() {
    enableStatic();
    StaticOtpChallengeVerifier verifier = new StaticOtpChallengeVerifier(props);

    // "sms" is not in the configured channels list (email, phone)
    assertThrows(
        SendOtpException.class,
        () -> verifier.sendOtp(TXN, INDIVIDUAL_ID, List.of("sms"), RP, CLIENT));
  }

  @Test
  void sendOtpFailsForEmptyChannelList() {
    enableStatic();
    StaticOtpChallengeVerifier verifier = new StaticOtpChallengeVerifier(props);

    assertThrows(
        SendOtpException.class,
        () -> verifier.sendOtp(TXN, INDIVIDUAL_ID, List.of(), RP, CLIENT));
  }

  @Test
  void sendOtpFailsForNullChannelList() {
    enableStatic();
    StaticOtpChallengeVerifier verifier = new StaticOtpChallengeVerifier(props);

    assertThrows(
        SendOtpException.class,
        () -> verifier.sendOtp(TXN, INDIVIDUAL_ID, null, RP, CLIENT));
  }

  // --- sendOtp non-enumerating ---

  @Test
  void sendOtpReturnsSameShapeForKnownAndUnknownSubject() throws Exception {
    enableStatic();
    StaticOtpChallengeVerifier verifier = new StaticOtpChallengeVerifier(props);

    SendOtpOutcome knownResult =
        verifier.sendOtp(TXN, "NID-KNOWN", List.of("email"), RP, CLIENT);
    SendOtpOutcome unknownResult =
        verifier.sendOtp(TXN, "NID-DOES-NOT-EXIST", List.of("email"), RP, CLIENT);

    // Both must return null masked values — the static verifier never sends a real OTP.
    assertNull(knownResult.getMaskedEmail(), "static verifier: maskedEmail must be null");
    assertNull(knownResult.getMaskedMobile(), "static verifier: maskedMobile must be null");
    assertNull(unknownResult.getMaskedEmail(), "static verifier: maskedEmail must be null");
    assertNull(unknownResult.getMaskedMobile(), "static verifier: maskedMobile must be null");
  }

  @Test
  void sendOtpDoesNotRevealSubjectExistenceInReturnValue() throws Exception {
    enableStatic();
    StaticOtpChallengeVerifier verifier = new StaticOtpChallengeVerifier(props);

    SendOtpOutcome result =
        verifier.sendOtp(TXN, "any-subject", List.of("email"), RP, CLIENT);

    // The result toString() must not include any subject-identifying information.
    String repr = result.toString();
    assertFalse(repr.contains("any-subject"), "toString must not contain subject value");
    assertFalse(repr.contains(INDIVIDUAL_ID), "toString must not contain individual ID");
  }

  // --- isSupportedOtpChannel ---

  @Test
  void isSupportedOtpChannelReturnsTrueForConfiguredChannels() {
    StaticOtpChallengeVerifier verifier = new StaticOtpChallengeVerifier(props);

    assertTrue(verifier.isSupportedOtpChannel("email"));
    assertTrue(verifier.isSupportedOtpChannel("phone"));
  }

  @Test
  void isSupportedOtpChannelReturnsFalseForUnconfiguredChannel() {
    StaticOtpChallengeVerifier verifier = new StaticOtpChallengeVerifier(props);

    assertFalse(verifier.isSupportedOtpChannel("sms"));
    assertFalse(verifier.isSupportedOtpChannel("push"));
    assertFalse(verifier.isSupportedOtpChannel(null));
  }

  // --- no OTP value appears in exception messages ---

  @Test
  void noOtpValueInAnyExceptionMessage() {
    enableStatic();
    StaticOtpChallengeVerifier verifier = new StaticOtpChallengeVerifier(props);

    // Wrong OTP
    try {
      verifier.verify(TXN, INDIVIDUAL_ID, List.of(otpChallenge("wrong")), RP, CLIENT);
    } catch (ChallengeVerificationException e) {
      String msg = e.getMessage() != null ? e.getMessage() : "";
      assertFalse(msg.contains("wrong"), "wrong OTP must not appear in message");
      assertFalse(msg.contains(STATIC_VALUE), "configured OTP must not appear in message");
    }
  }

  // --- helpers ---

  private void enableStatic() {
    props.getEsignet().getAuth().getOtp().setStaticEnabled(true);
  }

  private static AuthChallenge otpChallenge(String value) {
    AuthChallenge c = new AuthChallenge();
    c.setAuthFactorType("OTP");
    c.setFormat("alpha-numeric");
    c.setChallenge(value);
    return c;
  }
}
