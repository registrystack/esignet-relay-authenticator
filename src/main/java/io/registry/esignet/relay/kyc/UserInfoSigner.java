package io.registry.esignet.relay.kyc;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Serializes a UserInfo/KYC claim map and signs it as a compact RS256 JWS, and packages it for the
 * eSignet-requested response type.
 *
 * <p>The compact serialization is {@code base64url(header).base64url(payload).base64url(signature)}
 * with header <pre>{"alg":"RS256","kid":&lt;kid&gt;,"typ":"JWT"}</pre> and the signature computed
 * over {@code base64url(header) + "." + base64url(payload)} using {@code SHA256withRSA}. The
 * {@code kid} and {@code alg} match {@link KycSigningKeyService#getKid()} and
 * {@link KycSigningKeyService#getAlgorithm()}, which is the same key/algorithm reported by
 * {@code getAllKycSigningCertificates}, so relying parties can verify.
 *
 * <p>Base64url helpers mirror {@link KycTokenService} (no-padding URL encoder over UTF-8 bytes), so
 * the JWS encoding is consistent across the plugin.
 *
 * <p><b>JWE fail-closed (deliberate):</b> {@link #pack} throws
 * {@link UserInfoPackagingException} with code {@link #ERR_JWE_UNSUPPORTED} when the response type
 * requests JWE. The RP encryption public key required to produce a JWE is NOT available to the
 * plugin: {@code KycExchangeDto} carries no RP key, and the target eSignet {@code 1.8.0} integration
 * API exposes no runtime hook for the plugin to fetch it. Per spec we MUST NOT return unencrypted
 * data for a JWE request, so we fail closed instead. This would be unblocked if eSignet supplied the
 * RP encryption JWK/cert via the exchange DTO or an integration API, at which point {@code pack}
 * would encrypt the signed JWT to that key (JWS-then-JWE) rather than throwing.
 *
 * <p><b>Security:</b> never logs the signed token, claim values, or key material.
 */
public class UserInfoSigner {

  /** Stable code carried by the fail-closed JWE exception. */
  public static final String ERR_JWE_UNSUPPORTED = "relay_kyc_jwe_unsupported";

  private static final String TYP = "JWT";
  private static final String JCA_SIGNATURE_ALG = "SHA256withRSA";
  private static final String JWE_MARKER = "JWE";

  private final KycSigningKeyService signingKeyService;
  private final ObjectMapper objectMapper;

  /**
   * @param signingKeyService the signing key (private key + kid + algorithm)
   */
  public UserInfoSigner(KycSigningKeyService signingKeyService) {
    this(signingKeyService, new ObjectMapper());
  }

  /**
   * Test-seam constructor allowing a custom mapper.
   *
   * @param signingKeyService the signing key
   * @param objectMapper the JSON mapper used to serialize the claims payload
   */
  public UserInfoSigner(KycSigningKeyService signingKeyService, ObjectMapper objectMapper) {
    this.signingKeyService = Objects.requireNonNull(signingKeyService, "signingKeyService");
    this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
  }

  /**
   * Builds the encoded JWS header for the current signing key. Computed per call (the signing key
   * may be lazily loaded), but stable for a given key since kid/alg are deterministic.
   */
  private String encodedHeader() {
    // Build via Jackson so the algorithm/kid values are correctly JSON-escaped rather than spliced
    // into a hand-written string. LinkedHashMap keeps the stable alg/kid/typ ordering.
    Map<String, String> header = new LinkedHashMap<>();
    header.put("alg", signingKeyService.getAlgorithm());
    header.put("kid", signingKeyService.getKid());
    header.put("typ", TYP);
    try {
      return base64Url(objectMapper.writeValueAsBytes(header));
    } catch (Exception e) {
      throw new IllegalStateException("Failed to serialize JWS header", e);
    }
  }

  /**
   * Signs the given UserInfo/KYC claims as a compact RS256 JWS.
   *
   * @param userInfoClaims the claims to sign
   * @return the 3-part compact JWS serialization
   * @throws IllegalStateException if serialization or signing fails
   */
  public String sign(Map<String, Object> userInfoClaims) {
    String encodedPayload;
    try {
      byte[] payloadBytes = objectMapper.writeValueAsBytes(userInfoClaims);
      encodedPayload = base64Url(payloadBytes);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to serialize UserInfo payload", e);
    }

    String signingInput = encodedHeader() + "." + encodedPayload;
    String encodedSignature = rsaSign(signingInput);
    return signingInput + "." + encodedSignature;
  }

  /**
   * Packages the claims for the eSignet-requested response type.
   *
   * <p>When {@code userInfoResponseType} requests JWE (case-insensitive, contains {@code "JWE"}),
   * this fails closed with {@link UserInfoPackagingException} ({@link #ERR_JWE_UNSUPPORTED}) and
   * emits NO token — see the class Javadoc for why. Otherwise (null/empty/{@code "JWS"}) it returns
   * {@link #sign(Map)}.
   *
   * @param userInfoClaims the claims to package
   * @param userInfoResponseType the eSignet/RP-requested response type, may be {@code null}
   * @return the compact JWS serialization for JWS/unset response types
   * @throws UserInfoPackagingException with {@link #ERR_JWE_UNSUPPORTED} when JWE is requested
   */
  public String pack(Map<String, Object> userInfoClaims, String userInfoResponseType)
      throws UserInfoPackagingException {
    if (isJweRequested(userInfoResponseType)) {
      // Fail closed: never return unencrypted data for a JWE request.
      throw new UserInfoPackagingException(
          ERR_JWE_UNSUPPORTED,
          "JWE response type requested but the RP encryption key is not available to the plugin");
    }
    return sign(userInfoClaims);
  }

  /**
   * Returns whether {@code userInfoResponseType} requests JWE (case-insensitive, contains
   * {@code "JWE"}). The plugin cannot satisfy a JWE request — the RP encryption key is not available
   * to it — so callers should detect this BEFORE releasing any attributes from Relay and fail closed,
   * rather than releasing data and only then discovering it cannot be packaged. {@link #pack} also
   * guards on this as defense in depth.
   *
   * @param userInfoResponseType the eSignet/RP-requested response type, may be {@code null}
   * @return {@code true} if a JWE response is requested and therefore cannot be satisfied
   */
  public static boolean isJweRequested(String userInfoResponseType) {
    return userInfoResponseType != null
        && userInfoResponseType.toUpperCase().contains(JWE_MARKER);
  }

  private String rsaSign(String signingInput) {
    try {
      Signature signature = Signature.getInstance(JCA_SIGNATURE_ALG);
      signature.initSign(signingKeyService.getPrivateKey());
      signature.update(signingInput.getBytes(StandardCharsets.UTF_8));
      return base64Url(signature.sign());
    } catch (Exception e) {
      throw new IllegalStateException("Failed to sign UserInfo payload", e);
    }
  }

  private static String base64Url(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }
}
