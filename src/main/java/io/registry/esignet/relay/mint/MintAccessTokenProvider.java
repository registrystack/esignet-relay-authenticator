package io.registry.esignet.relay.mint;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.registry.esignet.relay.RelayAuthenticatorProperties;
import java.io.IOException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

/** Single-flight Registry Mint client-credentials token acquisition and bounded in-memory cache. */
public final class MintAccessTokenProvider {

  public static final String CLIENT_ASSERTION_TYPE =
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

  private final RelayAuthenticatorProperties.Mint config;
  private final HttpClient httpClient;
  private final ObjectMapper objectMapper;
  private final Clock clock;
  private final MintClientAssertionSigner signer;
  private char[] cachedToken;
  private Instant cachedUntil = Instant.EPOCH;

  public MintAccessTokenProvider(RelayAuthenticatorProperties properties) {
    this(
        properties,
        HttpClient.newBuilder()
            .connectTimeout(Duration.ofMillis(properties.getMint().getConnectTimeoutMs()))
            .build(),
        new ObjectMapper(),
        Clock.systemUTC());
  }

  public MintAccessTokenProvider(
      RelayAuthenticatorProperties properties,
      HttpClient httpClient,
      ObjectMapper objectMapper,
      Clock clock) {
    this.config = properties.getMint();
    this.httpClient = httpClient;
    this.objectMapper = objectMapper;
    this.clock = clock;
    this.signer =
        new MintClientAssertionSigner(
            objectMapper,
            clock,
            config.getClientId(),
            config.getTokenEndpoint(),
            config.getAssertionLifetimeSeconds(),
            config.getPrivateJwk());
  }

  /** Returns a caller-owned token copy. Closing it clears that copy. */
  public synchronized AccessToken accessToken() throws MintTokenException {
    Instant now = clock.instant();
    if (cachedToken != null && now.isBefore(cachedUntil)) {
      return new AccessToken(cachedToken.clone());
    }
    clearCachedToken();
    TokenResponse minted = mint(now);
    cachedToken = minted.token();
    long cacheSeconds = Math.min(minted.expiresIn(), config.getTokenCacheMaxSeconds());
    cachedUntil = now.plusSeconds(cacheSeconds);
    return new AccessToken(cachedToken.clone());
  }

  /** Clears a token Relay has rejected so the next request authenticates afresh. */
  public synchronized void invalidate() {
    clearCachedToken();
  }

  private TokenResponse mint(Instant now) throws MintTokenException {
    String assertion;
    try {
      assertion = signer.createAssertion();
    } catch (RuntimeException ignored) {
      throw new MintTokenException();
    }
    String form =
        "grant_type=client_credentials&client_assertion_type="
            + encode(CLIENT_ASSERTION_TYPE)
            + "&client_assertion="
            + encode(assertion);
    byte[] formBytes = form.getBytes(StandardCharsets.US_ASCII);
    try {
      HttpRequest request =
          HttpRequest.newBuilder()
              .uri(java.net.URI.create(config.getTokenEndpoint()))
              .timeout(Duration.ofMillis(config.getReadTimeoutMs()))
              .header("Content-Type", "application/x-www-form-urlencoded")
              .header("Accept", "application/json")
              .POST(HttpRequest.BodyPublishers.ofByteArray(formBytes))
              .build();
      HttpResponse<String> response =
          httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
      if (response.statusCode() != 200) {
        throw new MintTokenException();
      }
      JsonNode body = objectMapper.readTree(response.body());
      JsonNode token = body == null ? null : body.get("access_token");
      JsonNode tokenType = body == null ? null : body.get("token_type");
      JsonNode expiresIn = body == null ? null : body.get("expires_in");
      if (token == null
          || !token.isTextual()
          || token.textValue().isBlank()
          || tokenType == null
          || !tokenType.isTextual()
          || !"Bearer".equalsIgnoreCase(tokenType.textValue())
          || expiresIn == null
          || !expiresIn.isIntegralNumber()
          || !expiresIn.canConvertToLong()
          || expiresIn.longValue() <= 0) {
        throw new MintTokenException();
      }
      return new TokenResponse(token.textValue().toCharArray(), expiresIn.longValue());
    } catch (HttpTimeoutException ignored) {
      throw new MintTokenException();
    } catch (IOException ignored) {
      throw new MintTokenException();
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      throw new MintTokenException();
    } finally {
      Arrays.fill(formBytes, (byte) 0);
    }
  }

  private static String encode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }

  private void clearCachedToken() {
    if (cachedToken != null) {
      Arrays.fill(cachedToken, '\0');
      cachedToken = null;
    }
    cachedUntil = Instant.EPOCH;
  }

  private record TokenResponse(char[] token, long expiresIn) {}

  /** Ephemeral token copy that is cleared after the Relay request has been built. */
  public static final class AccessToken implements AutoCloseable {
    private final char[] value;

    private AccessToken(char[] value) {
      this.value = value;
    }

    public String authorizationValue() {
      return "Bearer " + new String(value);
    }

    @Override
    public void close() {
      Arrays.fill(value, '\0');
    }
  }
}
