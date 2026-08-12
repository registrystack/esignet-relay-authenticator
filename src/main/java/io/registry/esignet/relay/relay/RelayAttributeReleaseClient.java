package io.registry.esignet.relay.relay;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.registry.esignet.relay.RelayAuthenticatorProperties;
import io.registry.esignet.relay.mint.MintAccessTokenProvider;
import io.registry.esignet.relay.mint.MintTokenException;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Client for one Registry Relay V2 consultation lookup. */
public class RelayAttributeReleaseClient {

  private static final Logger log = LoggerFactory.getLogger(RelayAttributeReleaseClient.class);
  private final RelayAuthenticatorProperties properties;
  private final HttpClient httpClient;
  private final ObjectMapper objectMapper;
  private final MintAccessTokenProvider tokenProvider;
  private final Duration readTimeout;

  public RelayAttributeReleaseClient(RelayAuthenticatorProperties properties) {
    this(
        properties,
        HttpClient.newBuilder()
            .connectTimeout(Duration.ofMillis(properties.getRelay().getConnectTimeoutMs()))
            .build(),
        new ObjectMapper(),
        new MintAccessTokenProvider(properties));
  }

  public RelayAttributeReleaseClient(
      RelayAuthenticatorProperties properties,
      HttpClient httpClient,
      ObjectMapper objectMapper,
      MintAccessTokenProvider tokenProvider) {
    this.properties = properties;
    this.httpClient = httpClient;
    this.objectMapper = objectMapper;
    this.tokenProvider = tokenProvider;
    this.readTimeout = Duration.ofMillis(properties.getRelay().getReadTimeoutMs());
  }

  /** Looks up one UIN and requests exactly the supplied, pre-filtered Relay properties. */
  public RelayReleaseResult release(String subjectValue, List<String> claims)
      throws RelayReleaseException {
    if (subjectValue == null || subjectValue.isBlank() || claims == null || claims.isEmpty()) {
      throw new RelayReleaseException(RelayReleaseError.SUBJECT_DENIED);
    }
    URI uri = buildUri(claims);
    String body = buildRequestBody(subjectValue);
    HttpResponse<String> response;
    try (MintAccessTokenProvider.AccessToken token = tokenProvider.accessToken()) {
      HttpRequest request =
          HttpRequest.newBuilder()
              .uri(uri)
              .timeout(readTimeout)
              .header("Authorization", token.authorizationValue())
              .header("Content-Type", "application/json")
              .header("Accept", properties.getRelay().getAccept())
              .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
              .build();
      response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    } catch (MintTokenException ignored) {
      log.warn("Registry Mint token acquisition failed; Relay lookup is unavailable");
      throw new RelayReleaseException(RelayReleaseError.UNAVAILABLE);
    } catch (HttpTimeoutException ignored) {
      log.warn("Relay lookup timed out; failing closed as unavailable");
      throw new RelayReleaseException(RelayReleaseError.UNAVAILABLE);
    } catch (IOException ignored) {
      log.warn("Relay lookup transport failed; failing closed as unavailable");
      throw new RelayReleaseException(RelayReleaseError.UNAVAILABLE);
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      throw new RelayReleaseException(RelayReleaseError.UNAVAILABLE);
    }

    if (response.statusCode() == 200) {
      return parseSuccess(response.body());
    }
    throw mapError(response.body());
  }

  private URI buildUri(List<String> claims) {
    RelayAuthenticatorProperties.Relay relay = properties.getRelay();
    String base = relay.getBaseUrl().trim();
    if (base.endsWith("/")) {
      base = base.substring(0, base.length() - 1);
    }
    StringBuilder uri =
        new StringBuilder(base)
            .append("/v2/resources/")
            .append(encode(relay.getResource()))
            .append("/lookups/")
            .append(encode(relay.getLookup()))
            .append("?fields=");
    for (int index = 0; index < claims.size(); index++) {
      if (index > 0) {
        uri.append(',');
      }
      uri.append(encode(claims.get(index)));
    }
    if (relay.getAccessProfile() != null && !relay.getAccessProfile().isBlank()) {
      uri.append("&accessProfile=").append(encode(relay.getAccessProfile()));
    }
    return URI.create(uri.toString());
  }

  private String buildRequestBody(String subjectValue) {
    ObjectNode root = objectMapper.createObjectNode();
    root.putObject("selectors").put("uin", subjectValue);
    try {
      return objectMapper.writeValueAsString(root);
    } catch (IOException e) {
      throw new IllegalStateException("Relay request could not be serialized", e);
    }
  }

  private RelayReleaseResult parseSuccess(String body) throws RelayReleaseException {
    try {
      JsonNode root = objectMapper.readTree(body);
      JsonNode domainData = root == null ? null : root.path("data").get("domainData");
      if (domainData == null || !domainData.isObject()) {
        throw new IOException("Relay success envelope is invalid");
      }
      return new RelayReleaseResult(toValueMap(domainData));
    } catch (IOException | RuntimeException ignored) {
      log.warn("Relay success envelope was invalid; failing closed as unavailable");
      throw new RelayReleaseException(RelayReleaseError.UNAVAILABLE);
    }
  }

  private RelayReleaseException mapError(String body) {
    String code = null;
    try {
      JsonNode root = objectMapper.readTree(body);
      JsonNode value = root == null ? null : root.get("code");
      code = value != null && value.isTextual() ? value.textValue() : null;
    } catch (IOException | RuntimeException ignored) {
      log.warn("Relay problem document was invalid; failing closed as unavailable");
    }
    RelayReleaseError error = RelayReleaseError.fromCode(code);
    if (RelayReleaseError.isAuthenticationCode(code)) {
      tokenProvider.invalidate();
    }
    log.warn("Relay lookup failed with a value-free {} outcome", error);
    return new RelayReleaseException(error);
  }

  private static String encode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
  }

  private static Map<String, Object> toValueMap(JsonNode node) {
    Map<String, Object> out = new LinkedHashMap<>();
    Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
    while (fields.hasNext()) {
      Map.Entry<String, JsonNode> field = fields.next();
      out.put(field.getKey(), toJavaValue(field.getValue()));
    }
    return out;
  }

  private static Object toJavaValue(JsonNode value) {
    if (value == null || value.isNull()) return null;
    if (value.isTextual()) return value.textValue();
    if (value.isBoolean()) return value.booleanValue();
    if (value.isIntegralNumber()) return value.bigIntegerValue();
    if (value.isFloatingPointNumber()) return value.doubleValue();
    if (value.isArray()) {
      java.util.ArrayList<Object> values = new java.util.ArrayList<>();
      value.forEach(item -> values.add(toJavaValue(item)));
      return values;
    }
    if (value.isObject()) return toValueMap(value);
    return value.asText();
  }
}
