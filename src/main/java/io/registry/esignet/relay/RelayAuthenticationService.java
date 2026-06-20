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
import io.registry.esignet.relay.kyc.ClaimMapper;
import io.registry.esignet.relay.kyc.KycSigningKeyService;
import io.registry.esignet.relay.kyc.KycTokenClaims;
import io.registry.esignet.relay.kyc.KycTokenException;
import io.registry.esignet.relay.kyc.KycTokenService;
import io.registry.esignet.relay.kyc.UserInfoPackagingException;
import io.registry.esignet.relay.kyc.UserInfoSigner;
import io.registry.esignet.relay.relay.RelayAttributeReleaseClient;
import io.registry.esignet.relay.relay.RelayReleaseError;
import io.registry.esignet.relay.relay.RelayReleaseException;
import io.registry.esignet.relay.relay.RelayReleaseResult;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Base64;
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
 * {@link RelayAttributeReleaseClient}, {@link KycTokenService}, {@link ClaimMapper},
 * {@link UserInfoSigner}, {@link KycSigningKeyService}) are produced by
 * {@link RelayAuthenticatorConfiguration} under the same conditional gate and injected here.
 *
 * <p><b>M5 implements:</b> {@link #doKycAuth(String, String, KycAuthDto)}, its
 * {@code claimsMetadataRequired} overload, {@link #sendOtp}, and {@link #isSupportedOtpChannel}.
 *
 * <p><b>M6 implements:</b> {@link #getAllKycSigningCertificates()}, returning the X.509 certificate
 * for the JWS signing key with a {@code keyId} that matches the JWS header {@code kid}.
 *
 * <p><b>M7 implements:</b> {@link #doKycExchange(String, String, KycExchangeDto)} and
 * {@link #doVerifiedKycExchange(String, String, VerifiedKycExchangeDto)}, which verify the KYC token,
 * request only the consented + profile-filtered claims from Relay, map them into the eSignet UserInfo
 * (subject from the PSUT), and sign as RS256 JWS via {@link UserInfoSigner}. A JWE response request
 * fails closed ({@link UserInfoSigner#ERR_JWE_UNSUPPORTED}) and emits no token, because the RP
 * encryption key is not available to the plugin. The verified variant does NOT synthesize assurance
 * metadata — Relay V1 returns none and the plugin must not fabricate it — so it currently equals the
 * standard exchange output.
 *
 * <p><b>doKycAuth flow:</b> validate input → verify the challenge (no Relay call if it fails) →
 * account-check via Relay with the configured minimal claim list (default {@code ["individual_id"]},
 * so NO demographics are released before consent) → derive the PSUT → issue a short-lived KYC token
 * → return {@link KycAuthResult}.
 *
 * <p><b>doKycExchange flow:</b> validate input → verify the KYC token (no Relay call if the token is
 * bad) → reduce accepted claims to {@code intersection(accepted, profile)} → release via Relay → map
 * into the eSignet UserInfo (subject from the PSUT) → sign as JWS (fail closed on a JWE request).
 *
 * <p><b>Privacy:</b> logs carry only safe fields (transaction id, client id); never the individual
 * id, OTP, KYC token, bearer token, PSUT, or any released attribute value.
 */
@Component
@ConditionalOnProperty(
    value = "mosip.esignet.integration.authenticator",
    havingValue = RelayAuthenticationService.BEAN_NAME)
public class RelayAuthenticationService implements Authenticator {

  /** Conditional bean-loading value eSignet matches against. */
  public static final String BEAN_NAME = "RelayAuthenticationService";

  private static final Logger log = LoggerFactory.getLogger(RelayAuthenticationService.class);

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
  static final String ERR_KYC_SIGNING_UNAVAILABLE = "relay_kyc_signing_unavailable";
  static final String ERR_TOKEN_INVALID = "relay_auth_token_invalid";
  static final String ERR_TOKEN_EXPIRED = "relay_auth_token_expired";
  static final String ERR_KYC_EXCHANGE_FAILED = "relay_kyc_exchange_failed";
  static final String ERR_KYC_SIGNING_FAILED = "relay_kyc_signing_failed";

  private final RelayAuthenticatorProperties properties;
  private final ChallengeVerifier challengeVerifier;
  private final RelayAttributeReleaseClient relayClient;
  private final KycTokenService kycTokenService;
  private final ClaimMapper claimMapper;
  private final UserInfoSigner userInfoSigner;
  private final KycSigningKeyService signingKeyService;

  /**
   * Spring constructor injection. Collaborators are produced by
   * {@link RelayAuthenticatorConfiguration} under the same conditional gate.
   *
   * @param properties validated plugin configuration
   * @param challengeVerifier the configured challenge verifier
   * @param relayClient the Relay attribute-release client
   * @param kycTokenService the internal KYC token issuer/verifier and PSUT deriver
   * @param claimMapper the config-driven claim mapper (request planning + response mapping)
   * @param userInfoSigner the UserInfo/KYC JWS signer and response-type packager
   * @param signingKeyService the KYC signing-key service (private key + cert + kid)
   */
  @Autowired
  public RelayAuthenticationService(
      RelayAuthenticatorProperties properties,
      ChallengeVerifier challengeVerifier,
      RelayAttributeReleaseClient relayClient,
      KycTokenService kycTokenService,
      ClaimMapper claimMapper,
      UserInfoSigner userInfoSigner,
      KycSigningKeyService signingKeyService) {
    this.properties = Objects.requireNonNull(properties, "properties");
    this.challengeVerifier = Objects.requireNonNull(challengeVerifier, "challengeVerifier");
    this.relayClient = Objects.requireNonNull(relayClient, "relayClient");
    this.kycTokenService = Objects.requireNonNull(kycTokenService, "kycTokenService");
    this.claimMapper = Objects.requireNonNull(claimMapper, "claimMapper");
    this.userInfoSigner = Objects.requireNonNull(userInfoSigner, "userInfoSigner");
    this.signingKeyService = Objects.requireNonNull(signingKeyService, "signingKeyService");
  }

  /**
   * Backward-compatible test/convenience constructor that derives the M6 collaborators from
   * {@code properties}: a {@link ClaimMapper} from the configured claim map, and a TOLERANT
   * {@link KycSigningKeyService} (keystore opened lazily) with its {@link UserInfoSigner}. The
   * signing path therefore only fails when {@link #getAllKycSigningCertificates()} (or future
   * exchange signing) is actually invoked without a usable keystore — auth-only flows still work.
   *
   * @param properties validated plugin configuration
   * @param challengeVerifier the configured challenge verifier
   * @param relayClient the Relay attribute-release client
   * @param kycTokenService the internal KYC token issuer/verifier and PSUT deriver
   */
  public RelayAuthenticationService(
      RelayAuthenticatorProperties properties,
      ChallengeVerifier challengeVerifier,
      RelayAttributeReleaseClient relayClient,
      KycTokenService kycTokenService) {
    this(
        properties,
        challengeVerifier,
        relayClient,
        kycTokenService,
        new ClaimMapper(properties),
        KycSigningKeyService.lazyFromProperties(properties));
  }

  private RelayAuthenticationService(
      RelayAuthenticatorProperties properties,
      ChallengeVerifier challengeVerifier,
      RelayAttributeReleaseClient relayClient,
      KycTokenService kycTokenService,
      ClaimMapper claimMapper,
      KycSigningKeyService signingKeyService) {
    this(
        properties,
        challengeVerifier,
        relayClient,
        kycTokenService,
        claimMapper,
        new UserInfoSigner(signingKeyService),
        signingKeyService);
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
    return new KycAuthException(releaseErrorCode(error));
  }

  /**
   * Maps an internal {@link RelayReleaseError} to its stable plugin error code. Branches on the
   * outcome (which was derived from the RFC 9457 {@code code}, never the HTTP status). Fails closed on
   * anything unexpected: the collapsed {@link RelayReleaseError#SUBJECT_DENIED}, {@code UNKNOWN}, and
   * the {@code default} all map to one generic {@link #ERR_SUBJECT_DENIED} denial with no sub-reason.
   * Shared by {@code doKycAuth} and the KYC-exchange flow so the two stay consistent.
   */
  private static String releaseErrorCode(RelayReleaseError error) {
    switch (error) {
      case SUBJECT_DENIED:
        // Single collapsed denial — disclose no sub-reason.
        return ERR_SUBJECT_DENIED;
      case UNAVAILABLE:
      case SOURCE_UNAVAILABLE:
        return ERR_RELAY_UNAVAILABLE;
      case PROFILE_NOT_FOUND:
        return ERR_CONFIG_PROFILE_NOT_FOUND;
      case SCOPE_DENIED:
        return ERR_CONFIG_SCOPE_DENIED;
      case PURPOSE_REQUIRED:
        return ERR_CONFIG_PURPOSE_REQUIRED;
      case PURPOSE_DENIED:
        return ERR_CONFIG_PURPOSE_DENIED;
      case SUBJECT_INVALID:
        // Bad id type / malformed subject — a local/request validation problem.
        return ERR_INVALID_REQUEST;
      case UNKNOWN:
      default:
        // Fail closed on anything unexpected; treat as a generic subject denial (no disclosure).
        return ERR_SUBJECT_DENIED;
    }
  }

  /**
   * Maps a {@link RelayReleaseException} raised during KYC exchange to a {@link KycExchangeException}
   * using the SAME outcome → code mapping as {@link #mapReleaseException} for {@code doKycAuth}, so the
   * collapsed denial and configuration faults surface identically across flows.
   */
  private KycExchangeException mapReleaseExceptionForExchange(
      RelayReleaseException e, String transactionId, String clientId) {
    RelayReleaseError error = e.getError();
    log.warn("doKycExchange Relay release failed: {} (clientId={}, txn={})", error, clientId,
        transactionId);
    return new KycExchangeException(releaseErrorCode(error));
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
  // getAllKycSigningCertificates (M6)
  // ---------------------------------------------------------------------------

  /**
   * Returns the single KYC signing certificate matching the JWS signing key. The {@code keyId}
   * equals the JWS header {@code kid} ({@link KycSigningKeyService#getKid()}), so eSignet can publish
   * it and relying parties can verify signatures produced by {@link UserInfoSigner}. The certificate
   * is rendered as PEM and the validity window comes from the certificate's {@code notBefore}/
   * {@code notAfter}.
   *
   * @return a one-element list with the signing certificate
   * @throws KycSigningCertificateException ({@link #ERR_KYC_SIGNING_UNAVAILABLE}) if the signing
   *     configuration/keystore is unavailable or invalid
   */
  @Override
  public List<KycSigningCertificateData> getAllKycSigningCertificates()
      throws KycSigningCertificateException {
    try {
      String kid = signingKeyService.getKid();
      X509Certificate certificate = signingKeyService.getCertificate();
      String pem = toPem(certificate);
      ZoneId zone = ZoneId.systemDefault();
      LocalDateTime issuedAt =
          LocalDateTime.ofInstant(certificate.getNotBefore().toInstant(), zone);
      LocalDateTime expiryAt =
          LocalDateTime.ofInstant(certificate.getNotAfter().toInstant(), zone);

      log.info("getAllKycSigningCertificates served (kid={})", kid);
      return List.of(new KycSigningCertificateData(kid, pem, expiryAt, issuedAt));
    } catch (KycSigningCertificateException e) {
      throw e;
    } catch (Exception e) {
      // Signing config/keystore error. Do not leak key material or paths.
      log.warn("getAllKycSigningCertificates failed: signing key unavailable");
      throw new KycSigningCertificateException(ERR_KYC_SIGNING_UNAVAILABLE);
    }
  }

  /** Renders an X.509 certificate as PEM (base64 DER wrapped in BEGIN/END CERTIFICATE). */
  private static String toPem(X509Certificate certificate) throws KycSigningCertificateException {
    try {
      String base64 =
          Base64.getMimeEncoder(64, new byte[] {'\n'})
              .encodeToString(certificate.getEncoded());
      return "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----\n";
    } catch (Exception e) {
      throw new KycSigningCertificateException(ERR_KYC_SIGNING_UNAVAILABLE);
    }
  }

  // ---------------------------------------------------------------------------
  // doKycExchange / doVerifiedKycExchange (M7)
  // ---------------------------------------------------------------------------

  /**
   * Exchanges a verified KYC token for the consented, profile-filtered UserInfo, packaged as a signed
   * (RS256 JWS) KYC payload eSignet accepts.
   *
   * <p><b>Flow:</b> validate input → verify the KYC token (no Relay call if the token is bad) →
   * reduce the eSignet-accepted claims to {@code intersection(accepted, profile)} (protocol-derived
   * {@code sub}/{@code $psut} are populated locally, never requested) → call Relay attribute release
   * with that consented list → map the released claims into the eSignet UserInfo with {@code sub}
   * derived from the PSUT → sign as JWS via {@link UserInfoSigner}. A JWE response request fails
   * closed ({@link UserInfoSigner#ERR_JWE_UNSUPPORTED}) and emits no token, because the RP encryption
   * key is not available to the plugin.
   *
   * <p><b>Privacy:</b> logs carry only safe fields (transaction id, client id); never the individual
   * id, KYC token, PSUT, released attribute values, or the Relay body.
   */
  @Override
  public KycExchangeResult doKycExchange(
      String relyingPartyId, String clientId, KycExchangeDto kycExchangeDto)
      throws KycExchangeException {
    return exchange(relyingPartyId, clientId, kycExchangeDto);
  }

  /**
   * Verified-KYC exchange. {@link VerifiedKycExchangeDto} extends {@link KycExchangeDto}, so this runs
   * the IDENTICAL flow as {@link #doKycExchange} and returns the SAME signed claim values.
   *
   * <p><b>Why no assurance metadata is synthesized:</b> Relay V1's attribute-release endpoint does not
   * return verified-claims assurance metadata (no {@code verification}/{@code verified_claims}
   * provenance). Per spec we MUST NOT fabricate assurance evidence, so this variant currently equals
   * the standard exchange output rather than emitting fake {@code verification}/{@code verified_claims}
   * blocks. This would be unblocked once Relay returns verified-claim metadata, at which point this
   * method would package that provenance into the eSignet verified-claims structure.
   */
  @Override
  public KycExchangeResult doVerifiedKycExchange(
      String relyingPartyId, String clientId, VerifiedKycExchangeDto kycExchangeDto)
      throws KycExchangeException {
    // Relay V1 returns no verified-claims metadata; do NOT fabricate assurance evidence (see Javadoc).
    return exchange(relyingPartyId, clientId, kycExchangeDto);
  }

  /**
   * Shared KYC-exchange implementation for {@link #doKycExchange} and {@link #doVerifiedKycExchange}.
   * Implements the spec's "Suggested exchange flow": verify token → consented + profile-filtered
   * claims → Relay → map → sign.
   */
  private KycExchangeResult exchange(
      String relyingPartyId, String clientId, KycExchangeDto dto) throws KycExchangeException {

    // 1. Validate input. Fail closed on anything missing/blank.
    if (isBlank(relyingPartyId) || isBlank(clientId) || dto == null) {
      throw new KycExchangeException(ERR_INVALID_REQUEST);
    }
    String transactionId = dto.getTransactionId();
    String kycToken = dto.getKycToken();
    if (isBlank(transactionId) || isBlank(kycToken)) {
      throw new KycExchangeException(ERR_INVALID_REQUEST);
    }

    log.info("doKycExchange start (clientId={}, txn={})", clientId, transactionId);

    try {
      // 2. Verify the KYC token BEFORE any Relay call. A bad token must never reach Relay.
      KycTokenClaims claims;
      try {
        claims =
            kycTokenService.verify(
                kycToken, relyingPartyId, clientId, transactionId, dto.getIndividualId());
      } catch (KycTokenException e) {
        log.warn("doKycExchange KYC token verification failed: {} (clientId={}, txn={})",
            e.getKind(), clientId, transactionId);
        if (e.getKind() == KycTokenException.Kind.TOKEN_EXPIRED) {
          throw new KycExchangeException(ERR_TOKEN_EXPIRED);
        }
        throw new KycExchangeException(ERR_TOKEN_INVALID);
      }

      // 3. Subject identity comes from the verified token, never from the request.
      String subjectValue = claims.getSub();
      String subjectIdType = claims.getSid();

      // 4. Reduce accepted claims to the consented, profile-filtered Relay source list. sub/$psut are
      //    protocol-derived and populated locally — never requested from Relay.
      List<String> acceptedClaims =
          dto.getAcceptedClaims() == null ? List.of() : dto.getAcceptedClaims();
      List<String> relayClaims = claimMapper.relayClaimsFor(acceptedClaims);

      // 5. Call Relay attribute release with that consented list (the client omits the claims field
      //    when the list is empty).
      RelayReleaseResult relayResult;
      try {
        relayResult = relayClient.release(subjectValue, relayClaims);
      } catch (RelayReleaseException e) {
        throw mapReleaseExceptionForExchange(e, transactionId, clientId);
      }

      // 6. PSUT — the protocol subject the relying party sees.
      String psut =
          kycTokenService.derivePsut(relyingPartyId, clientId, subjectIdType, subjectValue);

      // 7. Map Relay's released claims into the eSignet UserInfo, sub derived from the PSUT.
      Map<String, Object> userInfo =
          claimMapper.toUserInfo(relayResult.getClaims(), psut, acceptedClaims);

      // 8. Package as signed JWS (fail closed on a JWE request; never return unencrypted data).
      String serialized;
      try {
        serialized = userInfoSigner.pack(userInfo, dto.getUserInfoResponseType());
      } catch (UserInfoPackagingException e) {
        log.warn("doKycExchange packaging failed: {} (clientId={}, txn={})", e.getCode(), clientId,
            transactionId);
        if (UserInfoSigner.ERR_JWE_UNSUPPORTED.equals(e.getCode())) {
          // Fail closed: emit no token for a JWE request we cannot satisfy.
          throw new KycExchangeException(UserInfoSigner.ERR_JWE_UNSUPPORTED);
        }
        throw new KycExchangeException(ERR_KYC_SIGNING_FAILED);
      }

      log.info("doKycExchange success (clientId={}, txn={})", clientId, transactionId);
      return new KycExchangeResult(serialized);
    } catch (KycExchangeException e) {
      // Already a stable, mapped exchange error — propagate as-is.
      throw e;
    } catch (RuntimeException e) {
      // Unexpected runtime failure — fail closed without leaking details.
      log.warn("doKycExchange failed unexpectedly (clientId={}, txn={})", clientId, transactionId);
      throw new KycExchangeException(ERR_KYC_EXCHANGE_FAILED);
    }
  }

  // --- helpers ---

  private static boolean isBlank(String s) {
    return s == null || s.isBlank();
  }
}
