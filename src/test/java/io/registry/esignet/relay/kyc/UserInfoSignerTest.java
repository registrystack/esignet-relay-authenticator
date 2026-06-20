package io.registry.esignet.relay.kyc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * M6 unit tests for {@link UserInfoSigner}: sign produces a verifiable RS256 JWS (header alg=RS256,
 * kid matches the signing key, signature verifies with the public key) and JWE response types fail
 * closed with {@link UserInfoSigner#ERR_JWE_UNSUPPORTED} without emitting a token.
 */
class UserInfoSignerTest {

  private final ObjectMapper mapper = new ObjectMapper();

  private TestSigningKeys.Bundle bundle;
  private KycSigningKeyService signingKeyService;
  private UserInfoSigner signer;

  @BeforeEach
  void setUp() {
    bundle = TestSigningKeys.generate();
    signingKeyService =
        new KycSigningKeyService(
            bundle.keyStore(), TestSigningKeys.ALIAS, TestSigningKeys.PASSWORD, "RS256");
    signer = new UserInfoSigner(signingKeyService, mapper);
  }

  @Test
  void signProducesVerifiableRs256JwsWithMatchingKid() throws Exception {
    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("sub", "psut-abc");
    claims.put("name", "Maria Santos");
    claims.put("age", 41);

    String jws = signer.sign(claims);

    String[] parts = jws.split("\\.", -1);
    assertEquals(3, parts.length, "compact JWS must have 3 parts");

    // Header assertions.
    Map<String, Object> header =
        mapper.readValue(
            Base64.getUrlDecoder().decode(parts[0]), new TypeReference<Map<String, Object>>() {});
    assertEquals("RS256", header.get("alg"), "header alg must be RS256");
    assertEquals("JWT", header.get("typ"));
    assertEquals(signingKeyService.getKid(), header.get("kid"), "header kid must match the signing key");

    // Payload round-trips (scalar types preserved).
    Map<String, Object> payload =
        mapper.readValue(
            Base64.getUrlDecoder().decode(parts[1]), new TypeReference<Map<String, Object>>() {});
    assertEquals("psut-abc", payload.get("sub"));
    assertEquals(41, payload.get("age"));

    // Signature verifies with the public key over base64url(header)+"."+base64url(payload).
    Signature verifier = Signature.getInstance("SHA256withRSA");
    verifier.initVerify(bundle.certificate().getPublicKey());
    verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8));
    boolean ok = verifier.verify(Base64.getUrlDecoder().decode(parts[2]));
    assertTrue(ok, "RS256 signature must verify with the public key");
  }

  @Test
  void packReturnsJwsForNullResponseType() throws Exception {
    String token = signer.pack(Map.of("sub", "psut-abc"), null);
    assertEquals(signer.sign(Map.of("sub", "psut-abc")).split("\\.")[0],
        token.split("\\.")[0], "JWS header is identical for the same key");
    assertEquals(3, token.split("\\.", -1).length);
  }

  @Test
  void packReturnsJwsForExplicitJwsResponseType() throws Exception {
    String token = signer.pack(Map.of("sub", "psut-abc"), "JWS");
    assertEquals(3, token.split("\\.", -1).length);
  }

  @Test
  void packFailsClosedForJweResponseTypeAndEmitsNoToken() {
    UserInfoPackagingException ex =
        assertThrows(
            UserInfoPackagingException.class,
            () -> signer.pack(Map.of("sub", "psut-abc"), "JWE"));
    assertEquals(UserInfoSigner.ERR_JWE_UNSUPPORTED, ex.getCode());
    assertEquals("relay_kyc_jwe_unsupported", ex.getCode());
    // No token must leak in the message.
    assertTrue(ex.getMessage() == null || !ex.getMessage().contains("."));
  }

  @Test
  void packFailsClosedForJweResponseTypeCaseInsensitive() {
    assertThrows(
        UserInfoPackagingException.class,
        () -> signer.pack(Map.of("sub", "psut-abc"), "jwe"));
    assertThrows(
        UserInfoPackagingException.class,
        () -> signer.pack(Map.of("sub", "psut-abc"), "JWS+JWE"));
  }
}
