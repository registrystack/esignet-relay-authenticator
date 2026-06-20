package io.registry.esignet.relay;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.mosip.esignet.api.dto.KycAuthDto;
import io.mosip.esignet.api.dto.KycAuthResult;
import io.mosip.esignet.api.dto.KycExchangeDto;
import io.mosip.esignet.api.dto.KycExchangeResult;
import io.mosip.esignet.api.dto.KycSigningCertificateData;
import io.mosip.esignet.api.dto.SendOtpDto;
import io.mosip.esignet.api.dto.SendOtpResult;
import io.mosip.esignet.api.dto.VerifiedKycExchangeDto;
import io.mosip.esignet.api.exception.KycAuthException;
import io.mosip.esignet.api.exception.KycExchangeException;
import io.mosip.esignet.api.exception.KycSigningCertificateException;
import io.mosip.esignet.api.exception.SendOtpException;
import io.mosip.esignet.api.spi.Authenticator;
import io.registry.esignet.relay.auth.ChallengeVerificationException;
import io.registry.esignet.relay.auth.ChallengeVerifier;
import io.registry.esignet.relay.auth.SendOtpOutcome;
import io.registry.esignet.relay.kyc.KycTokenService;
import io.registry.esignet.relay.relay.RelayAttributeReleaseClient;
import io.registry.esignet.relay.relay.RelayReleaseError;
import io.registry.esignet.relay.relay.RelayReleaseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * eSignet {@link Authenticator} backed by Registry Relay's governed attribute release endpoint.
 *
 * <p>Loaded by eSignet only when {@code mosip.esignet.integration.authenticator} equals
 * {@link #BEAN_NAME}. Its collaborators ({@link ChallengeVerifier},
 * {@link RelayAttributeReleaseClient}, {@link KycTokenService}) are produced by
 * {@link RelayAuthenticatorConfiguration} under the same conditional gate and injected here.
 *
 * <p><b>M5 implements:</b> {@link #doKycAuth(String, String, KycAuthDto)}, its
 * {@code claimsMetadataRequired} overload, {@link #sendOtp}, and {@link #isSupportedOtpChannel}.
 * {@code doKycExchange} / {@code doVerifiedKycExchange} / {@code getAllKycSigningCertificates}
 * remain stubbed for later milestones.
 *
 * <p><b>doKycAuth flow:</b> validate input → verify the challenge (no Relay call if it fails) →
 * account-check via Relay with the configured minimal claim list (default {@code ["individual_id"]},
 * so NO demographics are released before consent) → derive the PSUT → issue a short-lived KYC token
 * → return {@link KycAuthResult}.
 *
 * <p><b>Privacy:</b> logs carry only safe fields (transaction id, client id); never the individual
 * id, OTP, KYC token, bearer token, or any released attribute value.
 */
@Component
@ConditionalOnProperty(
    value = "mosip.esignet.integration.authenticator",
    havingValue = RelayAuthenticationService.BEAN_NAME)
public class RelayAuthenticationService implements Authenticator {

  /** Conditional bean-loading value eSignet matches against. */
  public static final String BEAN_NAME = "RelayAuthenticationService";

  private static final Logger log = LoggerFactory.getLogger(RelayAuthenticationService.class);

  private static final String NOT_IMPLEMENTED = "not_implemented";

  // --- Internal error codes (see docs/esignet-relay-authenticator-plugin-spec.md) ---
  static final String ERR_INVALID_REQUEST = "relay_auth_invalid_request";
  static final String ERR_CHALLENGE_FAILED = "relay_auth_challenge_failed";
  static final String ERR_SUBJECT_DENIED = "relay_auth_subject_denied";
  static final String ERR_RELAY_UNAVAILABLE = "relay_auth_relay_unavailable";
  static final String ERR_CONFIG_PROFILE_NOT_FOUND = "relay_config_profile_not_found";
  static final String ERR_CONFIG_SCOPE_DENIED = "relay_config_scope_denied";
  static final String ERR_CONFIG_PURPOSE_REQUIRED = "relay_config_purpose_required";
  static final String ERR_CONFIG_PURPOSE_DENIED = "relay_config_purpose_denied";
  static final String ERR_SEND_OTP_FAILED = "relay_send_otp_failed";

  private final RelayAuthenticatorProperties properties;
  private final ChallengeVerifier challengeVerifier;
  private final RelayAttributeReleaseClient relayClient;
  private final KycTokenService kycTokenService;

  /**
   * Spring constructor injection. Collaborators are produced by
   * {@link RelayAuthenticatorConfiguration} under the same conditional gate.
   *
   * @param properties validated plugin configuration
   * @param challengeVerifier the configured challenge verifier
   * @param relayClient the Relay attribute-release client
   * @param kycTokenService the internal KYC token issuer/verifier and PSUT deriver
   */
  @Autowired
  public RelayAuthenticationService(
      RelayAuthenticatorProperties properties,
      ChallengeVerifier challengeVerifier,
      RelayAttributeReleaseClient relayClient,
      KycTokenService kycTokenService) {
    this.properties = Objects.requireNonNull(properties, "properties");
    this.challengeVerifier = Objects.requireNonNull(challengeVerifier, "challengeVerifier");
    this.relayClient = Objects.requireNonNull(relayClient, "relayClient");
    this.kycTokenService = Objects.requireNonNull(kycTokenService, "kycTokenService");
  }

  // ---------------------------------------------------------------------------
  // doKycAuth
  // ---------------------------------------------------------------------------

  // The 3-arg overload is deprecated on the eSignet interface in favour of the 4-arg one, but it is
  // still abstract and must be implemented; we delegate to the 4-arg flow.
  @SuppressWarnings("deprecation")
  @Override
  public KycAuthResult doKycAuth(String relyingPartyId, String clientId, KycAuthDto kycAuthDto)
      throws KycAuthException {
    return doKycAuth(relyingPartyId, clientId, false, kycAuthDto);
  }

  @Override
  public KycAuthResult doKycAuth(
      String relyingPartyId, String clientId, boolean claimsMetadataRequired, KycAuthDto kycAuthDto)
      throws KycAuthException {

    // 1. Validate input. Fail closed on anything missing/blank.
    if (isBlank(relyingPartyId) || isBlank(clientId) || kycAuthDto == null) {
      throw new KycAuthException(ERR_INVALID_REQUEST);
    }
    String transactionId = kycAuthDto.getTransactionId();
    String individualId = kycAuthDto.getIndividualId();
    List<io.mosip.esignet.api.dto.AuthChallenge> challenges = kycAuthDto.getChallengeList();
    if (isBlank(transactionId)
        || isBlank(individualId)
        || challenges == null
        || challenges.isEmpty()) {
      throw new KycAuthException(ERR_INVALID_REQUEST);
    }

    log.info("doKycAuth start (clientId={}, txn={})", clientId, transactionId);

    // 2. Verify the challenge BEFORE any Relay call. A failed challenge must never reach Relay.
    List<String> amr;
    try {
      amr =
          challengeVerifier.verify(
              transactionId, individualId, challenges, relyingPartyId, clientId);
    } catch (ChallengeVerificationException e) {
      // Includes the disabled/unsupported-verifier case. Generic, non-revealing failure.
      log.warn("doKycAuth challenge verification failed (clientId={}, txn={})", clientId,
          transactionId);
      throw new KycAuthException(ERR_CHALLENGE_FAILED);
    }

    // 3. Account-check via Relay with the minimal claim list — proves the subject exists/releasable
    //    WITHOUT fetching demographics before consent.
    List<String> accountCheckClaims = properties.getEsignet().getAccountCheckClaims();
    try {
      relayClient.release(individualId, accountCheckClaims);
    } catch (RelayReleaseException e) {
      throw mapReleaseException(e, transactionId, clientId);
    }

    String subjectIdType = properties.getRelay().getSubject().getIdType();

    // 4. PSUT.
    String psut =
        kycTokenService.derivePsut(relyingPartyId, clientId, subjectIdType, individualId);

    // 5. Short-lived internal KYC token bound to rp/client/txn/subject.
    String kycToken =
        kycTokenService.issue(
            individualId, subjectIdType, relyingPartyId, clientId, transactionId, amr);

    log.info("doKycAuth success (clientId={}, txn={})", clientId, transactionId);

    // 6. Result, optionally with conservative claims metadata (no raw values).
    if (claimsMetadataRequired) {
      return new KycAuthResult(kycToken, psut, buildClaimsMetadata());
    }
    return new KycAuthResult(kycToken, psut);
  }

  /**
   * Maps a {@link RelayReleaseException} to the right eSignet {@link KycAuthException} error code.
   * Branches on the internal {@link RelayReleaseError} (which itself was derived from the RFC 9457
   * {@code code}, never the HTTP status). Fails closed on anything unexpected. The collapsed
   * {@link RelayReleaseError#SUBJECT_DENIED} maps to one generic denial with no sub-reason.
   */
  private KycAuthException mapReleaseException(
      RelayReleaseException e, String transactionId, String clientId) {
    RelayReleaseError error = e.getError();
    log.warn("doKycAuth Relay account-check failed: {} (clientId={}, txn={})", error, clientId,
        transactionId);
    switch (error) {
      case SUBJECT_DENIED:
        // Single collapsed denial — disclose no sub-reason.
        return new KycAuthException(ERR_SUBJECT_DENIED);
      case UNAVAILABLE:
      case SOURCE_UNAVAILABLE:
        return new KycAuthException(ERR_RELAY_UNAVAILABLE);
      case PROFILE_NOT_FOUND:
        return new KycAuthException(ERR_CONFIG_PROFILE_NOT_FOUND);
      case SCOPE_DENIED:
        return new KycAuthException(ERR_CONFIG_SCOPE_DENIED);
      case PURPOSE_REQUIRED:
        return new KycAuthException(ERR_CONFIG_PURPOSE_REQUIRED);
      case PURPOSE_DENIED:
        return new KycAuthException(ERR_CONFIG_PURPOSE_DENIED);
      case SUBJECT_INVALID:
        // Bad id type / malformed subject — a local/request validation problem.
        return new KycAuthException(ERR_INVALID_REQUEST);
      case UNKNOWN:
      default:
        // Fail closed on anything unexpected; treat as a generic subject denial (no disclosure).
        return new KycAuthException(ERR_SUBJECT_DENIED);
    }
  }

  /**
   * Builds conservative claims metadata describing ONLY the claim names the plugin could request from
   * Relay (the configured profile/account-check claim names), with NO raw values. Each entry is an
   * empty descriptor object so eSignet sees the claim is available without any data leakage.
   */
  private Map<String, List<JsonNode>> buildClaimsMetadata() {
    // Conservative set: the account-check claims plus any configured profile default claims.
    List<String> names = new ArrayList<>(properties.getEsignet().getAccountCheckClaims());
    for (String claim : properties.getRelay().getDefaultClaims()) {
      if (!names.contains(claim)) {
        names.add(claim);
      }
    }
    Map<String, List<JsonNode>> metadata = new LinkedHashMap<>();
    for (String name : names) {
      ObjectNode descriptor = JsonNodeFactory.instance.objectNode();
      // Name/structure only — never a raw value. Mark availability without disclosing anything.
      descriptor.put("available", true);
      metadata.put(name, List.of(descriptor));
    }
    return metadata;
  }

  // ---------------------------------------------------------------------------
  // sendOtp / isSupportedOtpChannel
  // ---------------------------------------------------------------------------

  @Override
  public SendOtpResult sendOtp(String relyingPartyId, String clientId, SendOtpDto sendOtpDto)
      throws SendOtpException {
    if (isBlank(relyingPartyId) || isBlank(clientId) || sendOtpDto == null) {
      throw new SendOtpException(ERR_SEND_OTP_FAILED);
    }
    String transactionId = sendOtpDto.getTransactionId();
    String individualId = sendOtpDto.getIndividualId();
    List<String> channels = sendOtpDto.getOtpChannels();
    if (isBlank(transactionId)) {
      throw new SendOtpException(ERR_SEND_OTP_FAILED);
    }

    log.info("sendOtp start (clientId={}, txn={})", clientId, transactionId);
    // Delegate to the (non-enumerating) verifier. It returns the same public shape regardless of
    // whether the subject exists, so success/failure here reveals nothing about the subject.
    SendOtpOutcome outcome =
        challengeVerifier.sendOtp(transactionId, individualId, channels, relyingPartyId, clientId);
    return new SendOtpResult(
        transactionId, outcome.getMaskedEmail(), outcome.getMaskedMobile());
  }

  @Override
  public boolean isSupportedOtpChannel(String channel) {
    return challengeVerifier.isSupportedOtpChannel(channel);
  }

  // ---------------------------------------------------------------------------
  // Stubbed for later milestones (M6/M7).
  // ---------------------------------------------------------------------------

  @Override
  public KycExchangeResult doKycExchange(
      String relyingPartyId, String clientId, KycExchangeDto kycExchangeDto)
      throws KycExchangeException {
    throw new KycExchangeException(NOT_IMPLEMENTED);
  }

  @Override
  public KycExchangeResult doVerifiedKycExchange(
      String relyingPartyId, String clientId, VerifiedKycExchangeDto kycExchangeDto)
      throws KycExchangeException {
    throw new KycExchangeException(NOT_IMPLEMENTED);
  }

  @Override
  public List<KycSigningCertificateData> getAllKycSigningCertificates()
      throws KycSigningCertificateException {
    throw new KycSigningCertificateException(NOT_IMPLEMENTED);
  }

  // --- helpers ---

  private static boolean isBlank(String s) {
    return s == null || s.isBlank();
  }
}
