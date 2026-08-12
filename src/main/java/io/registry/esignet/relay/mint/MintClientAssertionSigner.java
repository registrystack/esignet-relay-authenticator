package io.registry.esignet.relay.mint;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

/** Builds Registry Mint {@code private_key_jwt} assertions using JDK RS256 crypto. */
public final class MintClientAssertionSigner {

  private final ObjectMapper objectMapper;
  private final Clock clock;
  private final String clientId;
  private final String audience;
  private final int lifetimeSeconds;
  private final String kid;
  private final PrivateKey privateKey;

  public MintClientAssertionSigner(
      ObjectMapper objectMapper,
      Clock clock,
      String clientId,
      String audience,
      int lifetimeSeconds,
      String privateJwk) {
    this.objectMapper = objectMapper;
    this.clock = clock;
    this.clientId = clientId;
    this.audience = audience;
    this.lifetimeSeconds = lifetimeSeconds;
    ParsedKey parsed = parsePrivateJwk(objectMapper, privateJwk);
    this.kid = parsed.kid();
    this.privateKey = parsed.privateKey();
  }

  /** Validates the supported key source without exposing any private member in an error. */
  public static void validatePrivateJwk(String privateJwk) {
    parsePrivateJwk(new ObjectMapper(), privateJwk);
  }

  /** Returns a fresh, single-use assertion with an exact token-endpoint audience. */
  public String createAssertion() {
    if (clientId == null || clientId.isBlank() || audience == null || audience.isBlank()) {
      throw new IllegalStateException("Mint client assertion configuration is invalid");
    }
    if (lifetimeSeconds < 1 || lifetimeSeconds > 300) {
      throw new IllegalStateException("Mint client assertion lifetime is invalid");
    }
    Instant now = clock.instant();
    long issuedAt = now.getEpochSecond();

    ObjectNode header = objectMapper.createObjectNode();
    header.put("alg", "RS256");
    header.put("typ", "JWT");
    header.put("kid", kid);

    ObjectNode claims = objectMapper.createObjectNode();
    claims.put("iss", clientId);
    claims.put("sub", clientId);
    claims.put("aud", audience);
    claims.put("iat", issuedAt);
    claims.put("exp", issuedAt + lifetimeSeconds);
    claims.put("jti", UUID.randomUUID().toString());

    byte[] headerBytes = null;
    byte[] claimBytes = null;
    byte[] signingBytes = null;
    byte[] signatureBytes = null;
    try {
      headerBytes = objectMapper.writeValueAsBytes(header);
      claimBytes = objectMapper.writeValueAsBytes(claims);
      String signingInput = encode(headerBytes) + "." + encode(claimBytes);
      signingBytes = signingInput.getBytes(StandardCharsets.US_ASCII);
      Signature signature = Signature.getInstance("SHA256withRSA");
      signature.initSign(privateKey);
      signature.update(signingBytes);
      signatureBytes = signature.sign();
      return signingInput + "." + encode(signatureBytes);
    } catch (Exception ignored) {
      throw new IllegalStateException("Mint client assertion could not be created");
    } finally {
      clear(headerBytes);
      clear(claimBytes);
      clear(signingBytes);
      clear(signatureBytes);
    }
  }

  private static ParsedKey parsePrivateJwk(ObjectMapper objectMapper, String privateJwk) {
    try {
      JsonNode jwk = objectMapper.readTree(privateJwk);
      if (jwk == null
          || !"RSA".equals(requiredText(jwk, "kty"))
          || !"RS256".equals(requiredText(jwk, "alg"))) {
        throw new IllegalArgumentException("unsupported Mint private JWK");
      }
      String kid = requiredText(jwk, "kid");
      if (kid.isBlank()) {
        throw new IllegalArgumentException("Mint private JWK has no kid");
      }
      RSAPrivateCrtKeySpec spec =
          new RSAPrivateCrtKeySpec(
              integer(jwk, "n"),
              integer(jwk, "e"),
              integer(jwk, "d"),
              integer(jwk, "p"),
              integer(jwk, "q"),
              integer(jwk, "dp"),
              integer(jwk, "dq"),
              integer(jwk, "qi"));
      if (spec.getModulus().bitLength() < 2048) {
        throw new IllegalArgumentException("Mint RSA key is too small");
      }
      return new ParsedKey(kid, KeyFactory.getInstance("RSA").generatePrivate(spec));
    } catch (IllegalArgumentException e) {
      throw e;
    } catch (Exception ignored) {
      throw new IllegalArgumentException("invalid Mint private JWK");
    }
  }

  private static String requiredText(JsonNode node, String member) {
    JsonNode value = node.get(member);
    if (value == null || !value.isTextual() || value.textValue().isBlank()) {
      throw new IllegalArgumentException("Mint private JWK member is invalid");
    }
    return value.textValue();
  }

  private static BigInteger integer(JsonNode node, String member) {
    byte[] decoded = null;
    try {
      decoded = Base64.getUrlDecoder().decode(requiredText(node, member));
      if (decoded.length == 0) {
        throw new IllegalArgumentException("Mint private JWK integer is empty");
      }
      return new BigInteger(1, decoded);
    } finally {
      clear(decoded);
    }
  }

  private static String encode(byte[] value) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
  }

  private static void clear(byte[] value) {
    if (value != null) {
      Arrays.fill(value, (byte) 0);
    }
  }

  private record ParsedKey(String kid, PrivateKey privateKey) {}
}
