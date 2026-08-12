package io.registry.esignet.relay.mint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.registry.esignet.relay.TestProperties;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class MintClientAssertionSignerTest {
  private final ObjectMapper mapper = new ObjectMapper();

  @Test
  void assertionIsValidRs256AndEveryJtiIsFresh() throws Exception {
    Instant now = Instant.parse("2026-08-12T00:00:00Z");
    MintClientAssertionSigner signer =
        new MintClientAssertionSigner(
            mapper,
            Clock.fixed(now, ZoneOffset.UTC),
            "client-a",
            "https://mint.example.test/token",
            120,
            TestProperties.mintPrivateJwk());

    String first = signer.createAssertion();
    String second = signer.createAssertion();
    JsonNode claims = decode(first, 1);
    assertEquals("client-a", claims.path("iss").asText());
    assertEquals(claims.path("iss"), claims.path("sub"));
    assertEquals(
        "https://mint.example.test/token",
        claims.path("aud").asText(),
        "audience must be the exact current Registry Mint token_endpoint");
    assertEquals(now.getEpochSecond(), claims.path("iat").asLong());
    assertEquals(now.plusSeconds(120).getEpochSecond(), claims.path("exp").asLong());
    assertNotEquals(claims.path("jti"), decode(second, 1).path("jti"));
    assertTrue(verifies(first));
  }

  private boolean verifies(String assertion) throws Exception {
    String[] parts = assertion.split("\\.");
    JsonNode jwk = mapper.readTree(TestProperties.mintPrivateJwk());
    BigInteger modulus = unsigned(jwk.path("n").asText());
    BigInteger exponent = unsigned(jwk.path("e").asText());
    Signature verifier = Signature.getInstance("SHA256withRSA");
    verifier.initVerify(
        KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent)));
    verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
    return verifier.verify(Base64.getUrlDecoder().decode(parts[2]));
  }

  private JsonNode decode(String assertion, int segment) throws Exception {
    return mapper.readTree(Base64.getUrlDecoder().decode(assertion.split("\\.")[segment]));
  }

  private static BigInteger unsigned(String encoded) {
    return new BigInteger(1, Base64.getUrlDecoder().decode(encoded));
  }
}
