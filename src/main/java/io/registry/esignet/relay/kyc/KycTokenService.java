package io.registry.esignet.relay.kyc;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.registry.esignet.relay.RelayAuthenticatorProperties;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Issues and verifies short-lived HS256 KYC tokens and derives partner-specific user tokens
 * (PSUT).
 *
 * <p>The KYC token is a compact JWS (Base64url-header.Base64url-payload.Base64url-signature)
 * using {@code HmacSHA256}. It binds to relying party, OIDC client, eSignet transaction ID, and
 * individual subject so that a stolen token cannot be replayed against a different party. The token
 * is short-lived (TTL from config) and carries a random {@code jti}.
 *
 * <p>Token format:
 * <pre>
 * Header (Base64url):  {"alg":"HS256","typ":"JWT"}
 * Payload (Base64url): {
 *   "iss":"esignet-relay-authenticator",
 *   "aud":"esignet-kyc-exchange",
 *   "sub":"&lt;subject value&gt;",
 *   "sid":"&lt;subject id type&gt;",
 *   "rp":"&lt;relyingPartyId&gt;",
 *   "client_id":"&lt;clientId&gt;",
 *   "txn":"&lt;transactionId&gt;",
 *   "amr":["OTP"],
 *   "iat":&lt;seconds&gt;,
 *   "exp":&lt;seconds&gt;,
 *   "jti":"&lt;uuid&gt;"
 * }
 * Signature: HMAC-SHA256(kycTokenSecret, base64url(header) + "." + base64url(payload))
 * </pre>
 *
 * <p>PSUT derivation (each component is base64url-encoded before joining so the {@code |} delimiter
 * can never collide across components):
 * <pre>
 * base64url(HMAC-SHA256(psutSecret, b64(relyingPartyId) + "|" + b64(clientId) + "|" + b64(subjectIdType) + "|" + b64(subjectValue)))
 * </pre>
 *
 * <p><b>Security:</b>
 * <ul>
 *   <li>Secrets are loaded from config and validated at construction time.
 *   <li>Signature comparison uses constant-time {@link MessageDigest#isEqual}.
 *   <li>No secret, raw token, or subject value is ever logged.
 *   <li>The KYC token secret and PSUT secret are separate.
 * </ul>
 *
 * <p><b>No new dependencies.</b> Uses only {@code javax.crypto.Mac}, {@code java.util.Base64}, and
 * Jackson (already a provided dep).
 */
public class KycTokenService {

  private static final Logger log = LoggerFactory.getLogger(KycTokenService.class);

  static final String ISSUER = "esignet-relay-authenticator";
  static final String AUDIENCE = "esignet-kyc-exchange";
  static final String HMAC_ALG = "HmacSHA256";
  static final String JWT_ALG = "HS256";
  static final String JWT_TYP = "JWT";

  // Pre-encoded static header: {"alg":"HS256","typ":"JWT"}
  private static final String ENCODED_HEADER;

  static {
    String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    ENCODED_HEADER = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(header.getBytes(StandardCharsets.UTF_8));
  }

  private final RelayAuthenticatorProperties properties;
  private final ObjectMapper objectMapper;
  private final Clock clock;

  /**
   * Builds the service and eagerly validates that both HMAC secrets are present and non-trivial.
   *
   * @param properties validated plugin configuration
   * @throws IllegalStateException if either HMAC secret is blank or absent
   */
  public KycTokenService(RelayAuthenticatorProperties properties) {
    this(properties, new ObjectMapper(), Clock.systemUTC());
  }

  /**
   * Test-seam constructor allowing a custom clock and mapper.
   *
   * @param properties validated plugin configuration
   * @param objectMapper the JSON mapper to use for token serialization/parsing
   * @param clock the clock to use for {@code iat}/{@code exp}
   */
  public KycTokenService(
      RelayAuthenticatorProperties properties, ObjectMapper objectMapper, Clock clock) {
    this.properties = Objects.requireNonNull(properties, "properties");
    this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    this.clock = Objects.requireNonNull(clock, "clock");
    validateSecrets();
  }

  private void validateSecrets() {
    String kycSecret = properties.getEsignet().getKycToken().getHmacSecret();
    if (kycSecret == null || kycSecret.isBlank()) {
      throw new IllegalStateException(
          "registry.esignet.kyc-token.hmac-secret must be set and non-trivial");
    }
    String psutSecret = properties.getEsignet().getPsut().getHmacSecret();
    if (psutSecret == null || psutSecret.isBlank()) {
      throw new IllegalStateException(
          "registry.esignet.psut.hmac-secret must be set and non-trivial");
    }
  }

  /**
   * Issues a signed KYC token binding the given context.
   *
   * @param subjectValue the raw Relay subject value (not logged)
   * @param subjectIdType the subject id type, for example {@code "national_id"}
   * @param relyingPartyId the relying party ID
   * @param clientId the OIDC client ID
   * @param transactionId the eSignet transaction ID
   * @param amr the verified authentication methods
   * @return the compact JWS token string
   * @throws IllegalStateException if token serialization or signing fails
   */
  public String issue(
      String subjectValue,
      String subjectIdType,
      String relyingPartyId,
      String clientId,
      String transactionId,
      List<String> amr) {
    long now = clock.instant().getEpochSecond();
    int ttl = properties.getEsignet().getKycToken().getTtlSeconds();
    String jti = UUID.randomUUID().toString();

    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("iss", ISSUER);
    claims.put("aud", AUDIENCE);
    claims.put("sub", subjectValue);
    claims.put("sid", subjectIdType);
    claims.put("rp", relyingPartyId);
    claims.put("client_id", clientId);
    claims.put("txn", transactionId);
    claims.put("amr", amr != null ? amr : List.of());
    claims.put("iat", now);
    claims.put("exp", now + ttl);
    claims.put("jti", jti);

    String encodedPayload;
    try {
      byte[] payloadBytes = objectMapper.writeValueAsBytes(claims);
      encodedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadBytes);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to serialize KYC token payload", e);
    }

    String signingInput = ENCODED_HEADER + "." + encodedPayload;
    String encodedSignature = hmacSign(kycTokenSecret(), signingInput);

    return signingInput + "." + encodedSignature;
  }

  /**
   * Verifies a KYC token and returns its parsed claims.
   *
   * <p>Checks in order:
   * <ol>
   *   <li>Structure (exactly 3 dot-separated parts).
   *   <li>Header: {@code alg=HS256}, {@code typ=JWT}.
   *   <li>Signature (constant-time).
   *   <li>Required claims: {@code iss}, {@code aud}, {@code sub}, {@code exp}, {@code rp},
   *       {@code client_id}, {@code txn}.
   *   <li>Expiry: {@code exp} must be strictly in the future.
   *   <li>Binding: {@code rp}, {@code client_id}, {@code txn} must match {@code expectedRp},
   *       {@code expectedClientId}, {@code expectedTxn}.
   *   <li>Individual ID binding: when {@code expectedIndividualId} is non-null, {@code sub} must
   *       match it.
   * </ol>
   *
   * @param token the compact JWS token string (never logged)
   * @param expectedRp expected relying party ID
   * @param expectedClientId expected OIDC client ID
   * @param expectedTxn expected eSignet transaction ID
   * @param expectedIndividualId the expected subject value, or {@code null} to skip this check
   * @return parsed, verified {@link KycTokenClaims}
   * @throws KycTokenException with {@link KycTokenException.Kind#TOKEN_EXPIRED} when the token has
   *     expired; {@link KycTokenException.Kind#TOKEN_INVALID} for any other failure
   */
  public KycTokenClaims verify(
      String token,
      String expectedRp,
      String expectedClientId,
      String expectedTxn,
      String expectedIndividualId)
      throws KycTokenException {

    // 1. Structure
    if (token == null) {
      throw invalid("token is null");
    }
    String[] parts = token.split("\\.", -1);
    if (parts.length != 3) {
      throw invalid("token must have exactly 3 parts");
    }

    String encodedHeader = parts[0];
    String encodedPayload = parts[1];
    String encodedSignature = parts[2];

    // 2. Header
    Map<String, Object> header;
    try {
      byte[] headerBytes = Base64.getUrlDecoder().decode(encodedHeader);
      header = objectMapper.readValue(headerBytes, new TypeReference<Map<String, Object>>() {});
    } catch (Exception e) {
      throw invalid("header could not be parsed", e);
    }
    if (!JWT_ALG.equals(header.get("alg"))) {
      throw invalid("unsupported or missing alg in header");
    }
    if (!JWT_TYP.equals(header.get("typ"))) {
      throw invalid("wrong or missing typ in header");
    }

    // 3. Signature (constant-time)
    String signingInput = encodedHeader + "." + encodedPayload;
    String expectedSignature = hmacSign(kycTokenSecret(), signingInput);
    byte[] actualSigBytes = encodedSignature.getBytes(StandardCharsets.UTF_8);
    byte[] expectedSigBytes = expectedSignature.getBytes(StandardCharsets.UTF_8);
    if (!MessageDigest.isEqual(actualSigBytes, expectedSigBytes)) {
      throw invalid("signature verification failed");
    }

    // 4. Parse payload
    Map<String, Object> payload;
    try {
      byte[] payloadBytes = Base64.getUrlDecoder().decode(encodedPayload);
      payload = objectMapper.readValue(payloadBytes, new TypeReference<Map<String, Object>>() {});
    } catch (Exception e) {
      throw invalid("payload could not be parsed", e);
    }

    // 5. Required claim presence
    String iss = stringClaim(payload, "iss");
    String aud = stringClaim(payload, "aud");
    String sub = stringClaim(payload, "sub");
    String sid = stringClaim(payload, "sid");
    String rp = stringClaim(payload, "rp");
    String clientId = stringClaim(payload, "client_id");
    String txn = stringClaim(payload, "txn");
    String jti = stringClaim(payload, "jti");
    long iat = longClaim(payload, "iat");
    long exp = longClaim(payload, "exp");
    List<String> amr = listStringClaim(payload, "amr");

    // 6. Expiry — checked before binding so we can give the right exception kind
    long nowSecs = clock.instant().getEpochSecond();
    if (exp <= nowSecs) {
      log.warn("KYC token has expired");
      throw new KycTokenException(KycTokenException.Kind.TOKEN_EXPIRED, "token_expired");
    }

    // 7. Binding checks
    if (!ISSUER.equals(iss)) {
      throw invalid("iss mismatch");
    }
    if (!AUDIENCE.equals(aud)) {
      throw invalid("aud mismatch");
    }
    if (!constantEqual(rp, expectedRp)) {
      throw invalid("rp mismatch");
    }
    if (!constantEqual(clientId, expectedClientId)) {
      throw invalid("client_id mismatch");
    }
    if (!constantEqual(txn, expectedTxn)) {
      throw invalid("txn mismatch");
    }
    if (expectedIndividualId != null && !constantEqual(sub, expectedIndividualId)) {
      throw invalid("sub (individual ID) mismatch");
    }

    return new KycTokenClaims(iss, aud, sub, sid, rp, clientId, txn, amr, jti, iat, exp);
  }

  /**
   * Derives a deterministic, partner-specific user token (PSUT).
   *
   * <p>Formula: {@code base64url(HMAC-SHA256(psutSecret, b64(rp) + "|" + b64(clientId) + "|" + b64(sidType) + "|" + b64(subjectValue)))}
   *
   * <p>The PSUT is stable for the same inputs, so a relying party always sees the same subject
   * identifier for the same individual. It differs across RP/client/subject combinations, preventing
   * cross-RP linkage from the PSUT value alone.
   *
   * <p>Each component is base64url-encoded before being joined with {@code |}. Because the base64url
   * alphabet excludes {@code |}, distinct {@code (rp, clientId, sidType, subjectValue)} tuples can
   * never produce the same input string — a {@code clientId} or {@code rp} that itself contained a
   * raw {@code |} could otherwise collide two different parties onto the same PSUT and break the
   * pairwise-pseudonym guarantee.
   *
   * @param relyingPartyId the relying party ID
   * @param clientId the OIDC client ID
   * @param subjectIdType the subject id type
   * @param subjectValue the raw subject value (not logged)
   * @return the PSUT — a Base64url-encoded HMAC with no padding
   */
  public String derivePsut(
      String relyingPartyId, String clientId, String subjectIdType, String subjectValue) {
    String input =
        b64Component(relyingPartyId)
            + "|"
            + b64Component(clientId)
            + "|"
            + b64Component(subjectIdType)
            + "|"
            + b64Component(subjectValue);
    return hmacSign(psutSecret(), input);
  }

  /** Base64url-encodes one PSUT component (UTF-8, no padding); null is treated as empty. */
  private static String b64Component(String value) {
    byte[] bytes = (value == null ? "" : value).getBytes(StandardCharsets.UTF_8);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  // --- private helpers ---

  private String kycTokenSecret() {
    return properties.getEsignet().getKycToken().getHmacSecret();
  }

  private String psutSecret() {
    return properties.getEsignet().getPsut().getHmacSecret();
  }

  /**
   * Computes {@code HMAC-SHA256(secret, data)} and returns the Base64url-encoded result (no
   * padding).
   */
  private static String hmacSign(String secret, String data) {
    try {
      Mac mac = Mac.getInstance(HMAC_ALG);
      SecretKeySpec keySpec =
          new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_ALG);
      mac.init(keySpec);
      byte[] digest = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    } catch (NoSuchAlgorithmException e) {
      // HmacSHA256 is required by the JCA spec; this should never happen.
      throw new IllegalStateException("HmacSHA256 not available", e);
    } catch (InvalidKeyException e) {
      throw new IllegalStateException("Invalid HMAC key", e);
    }
  }

  /** Constant-time string equality to prevent timing side-channels on secret values. */
  private static boolean constantEqual(String a, String b) {
    if (a == null || b == null) {
      return a == b;
    }
    return MessageDigest.isEqual(
        a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
  }

  private static String stringClaim(Map<String, Object> map, String key)
      throws KycTokenException {
    Object v = map.get(key);
    if (v == null) {
      throw new KycTokenException(
          KycTokenException.Kind.TOKEN_INVALID, "missing required claim: " + key);
    }
    return v.toString();
  }

  private static long longClaim(Map<String, Object> map, String key) throws KycTokenException {
    Object v = map.get(key);
    if (v instanceof Number) {
      return ((Number) v).longValue();
    }
    throw new KycTokenException(
        KycTokenException.Kind.TOKEN_INVALID, "missing or non-numeric claim: " + key);
  }

  @SuppressWarnings("unchecked")
  private static List<String> listStringClaim(Map<String, Object> map, String key) {
    Object v = map.get(key);
    if (v instanceof List) {
      return (List<String>) v;
    }
    return List.of();
  }

  private static KycTokenException invalid(String reason) {
    return new KycTokenException(KycTokenException.Kind.TOKEN_INVALID, "token_invalid: " + reason);
  }

  private static KycTokenException invalid(String reason, Throwable cause) {
    return new KycTokenException(
        KycTokenException.Kind.TOKEN_INVALID, "token_invalid: " + reason, cause);
  }
}
