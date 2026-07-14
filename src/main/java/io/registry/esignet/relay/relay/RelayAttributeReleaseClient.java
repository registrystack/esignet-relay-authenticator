package io.registry.esignet.relay.relay;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.registry.esignet.relay.RelayAuthenticatorProperties;
import java.io.IOException;
import java.net.URI;
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

/**
 * Client for the Registry Relay governed attribute-release endpoint.
 *
 * <p>Issues {@code POST {base-url}{path-template}} with {@code {profile_id}}/{@code {version}}
 * substituted from configuration, reloads the bearer token from its configured file, sends it as
 * {@code Authorization: Bearer} (never {@code X-API-Key}), and branches errors on the RFC 9457
 * {@code code} extension, never on the HTTP status. Connect/read timeouts come from {@link
 * RelayAuthenticatorProperties}.
 *
 * <p><b>Claim-filtering contract:</b> this client sends <em>exactly</em> the claim list it is given.
 * Reducing the eSignet-accepted claims to {@code intersection(accepted, profile/config-declared)} —
 * required because Relay V1 denies the entire request if any requested claim is outside the profile —
 * is a caller responsibility handled in a later milestone, not here.
 *
 * <p><b>Privacy:</b> never logs the subject value, the bearer token, the requested claim values, the
 * released claim values, or the raw response body. Only coarse, non-identifying signals (the internal
 * outcome) are logged.
 */
public class RelayAttributeReleaseClient {

  private static final Logger log = LoggerFactory.getLogger(RelayAttributeReleaseClient.class);

  private static final String HDR_AUTHORIZATION = "Authorization";
  private static final String HDR_DATA_PURPOSE = "Data-Purpose";
  private static final String HDR_CONTENT_TYPE = "Content-Type";
  private static final String HDR_ACCEPT = "Accept";
  private static final String CONTENT_TYPE_JSON = "application/json";

  private final RelayAuthenticatorProperties properties;
  private final HttpClient httpClient;
  private final ObjectMapper objectMapper;
  private final Duration readTimeout;
  private final RelayBearerTokenFile bearerTokenFile;

  /**
   * Builds a client with an {@link HttpClient} configured from the connect timeout in {@code
   * properties}.
   *
   * @param properties validated plugin configuration
   */
  public RelayAttributeReleaseClient(RelayAuthenticatorProperties properties) {
    this(
        properties,
        HttpClient.newBuilder()
            .connectTimeout(Duration.ofMillis(properties.getRelay().getConnectTimeoutMs()))
            .build(),
        new ObjectMapper());
  }

  /**
   * Test/seam constructor allowing a pre-built {@link HttpClient} and {@link ObjectMapper}.
   *
   * @param properties validated plugin configuration
   * @param httpClient the HTTP client to use
   * @param objectMapper the JSON mapper to use
   */
  public RelayAttributeReleaseClient(
      RelayAuthenticatorProperties properties, HttpClient httpClient, ObjectMapper objectMapper) {
    this.properties = properties;
    this.httpClient = httpClient;
    this.objectMapper = objectMapper;
    this.readTimeout = Duration.ofMillis(properties.getRelay().getReadTimeoutMs());
    this.bearerTokenFile =
        new RelayBearerTokenFile(properties.getRelay().getAuth().getBearerTokenFile());
  }

  /**
   * Calls the attribute-release endpoint for one subject and the given claim list.
   *
   * @param subjectValue the raw subject value (for example a national id); travels only in the POST
   *     body, never the URL/query, and is never logged
   * @param claims the exact claim list to request; sent verbatim (see class javadoc on filtering)
   * @return the typed success result
   * @throws RelayReleaseException with a mapped {@link RelayReleaseError} for any error or
   *     transport-level failure
   */
  public RelayReleaseResult release(String subjectValue, List<String> claims)
      throws RelayReleaseException {
    URI uri = buildUri();
    String body = buildRequestBody(subjectValue, claims);
    String bearerToken;
    try {
      bearerToken = bearerTokenFile.read();
    } catch (RelayBearerTokenFile.CredentialException e) {
      log.warn("Relay bearer credential is unavailable or invalid; failing closed");
      // Do not retain the credential exception as a cause. Even though it is sanitized today, this
      // keeps future filesystem implementation details out of exceptions that cross this boundary.
      throw new RelayReleaseException(RelayReleaseError.UNAVAILABLE, null, null);
    }

    HttpRequest.Builder requestBuilder =
        HttpRequest.newBuilder()
            .uri(uri)
            .timeout(readTimeout)
            .header(HDR_AUTHORIZATION, "Bearer " + bearerToken)
            .header(HDR_CONTENT_TYPE, CONTENT_TYPE_JSON)
            .header(HDR_ACCEPT, properties.getRelay().getAttributeRelease().getAccept())
            .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));

    // Data-Purpose is required by the governed profile and validated non-blank at startup
    // (RelayAuthenticatorProperties#validate), so in a valid deployment it is always sent. The
    // null/blank guard here is purely defensive — it avoids emitting a malformed empty header should
    // the client ever be constructed without that validation (e.g. in isolation).
    String purpose = properties.getRelay().getAttributeRelease().getPurpose();
    if (purpose != null && !purpose.isBlank()) {
      requestBuilder.header(HDR_DATA_PURPOSE, purpose);
    }

    HttpResponse<String> response;
    try {
      response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
    } catch (HttpTimeoutException e) {
      // HttpConnectTimeoutException is a subclass and is caught here too.
      log.warn("Relay attribute release timed out; failing closed as unavailable");
      throw new RelayReleaseException(RelayReleaseError.UNAVAILABLE, null, e);
    } catch (IOException e) {
      log.warn("Relay attribute release transport failure; failing closed as unavailable");
      throw new RelayReleaseException(RelayReleaseError.UNAVAILABLE, null, e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new RelayReleaseException(RelayReleaseError.UNAVAILABLE, null, e);
    }

    if (response.statusCode() == 200) {
      return parseSuccess(response.body());
    }
    throw mapError(response.body());
  }

  private URI buildUri() {
    String base = properties.getRelay().getBaseUrl().trim();
    if (base.endsWith("/")) {
      base = base.substring(0, base.length() - 1);
    }
    RelayAuthenticatorProperties.Relay.AttributeRelease ar =
        properties.getRelay().getAttributeRelease();
    String path =
        ar.getPathTemplate()
            .replace("{profile_id}", encodePathSegment(ar.getProfileId()))
            .replace("{version}", encodePathSegment(ar.getProfileVersion()));
    return URI.create(base + path);
  }

  private static String encodePathSegment(String value) {
    // Profile id/version are operator-configured and simple; encode spaces defensively only.
    return value == null ? "" : value.replace(" ", "%20");
  }

  private String buildRequestBody(String subjectValue, List<String> claims) {
    ObjectNode root = objectMapper.createObjectNode();
    ObjectNode subject = root.putObject("subject");
    subject.put("id_type", properties.getRelay().getSubject().getIdType());
    subject.put("value", subjectValue);
    // Relay's request is strict (serde deny_unknown_fields) and an explicit empty `claims` array is a
    // 400. When the caller passes null/empty, OMIT the field entirely so Relay applies the profile's
    // default claim set. Only a non-empty list is serialized.
    if (claims != null && !claims.isEmpty()) {
      var array = root.putArray("claims");
      for (String claim : claims) {
        array.add(claim);
      }
    }
    try {
      return objectMapper.writeValueAsString(root);
    } catch (IOException e) {
      // Serializing a node we just built does not throw in practice; treat as unavailable.
      throw new IllegalStateException("failed to serialize Relay request body", e);
    }
  }

  private RelayReleaseResult parseSuccess(String body) throws RelayReleaseException {
    try {
      JsonNode root = objectMapper.readTree(body);
      String profileId = textOrNull(root, "profile_id");
      String profileVersion = textOrNull(root, "profile_version");
      Map<String, Object> claims = toScalarMap(root.get("claims"));
      // `source` may be gated off by the profile's include_source_metadata config; treat an absent
      // object as null (optional) rather than failing or fabricating an empty block.
      JsonNode sourceNode = root.get("source");
      Map<String, Object> source =
          sourceNode == null || !sourceNode.isObject() ? null : toScalarMap(sourceNode);
      return new RelayReleaseResult(profileId, profileVersion, claims, source);
    } catch (IOException e) {
      log.warn("Relay success body could not be parsed; failing closed");
      throw new RelayReleaseException(RelayReleaseError.UNKNOWN, null, e);
    }
  }

  /**
   * Maps an error response to a {@link RelayReleaseException}. Parses the RFC 9457 {@code
   * application/problem+json} body and branches on {@code code}. The collapsed {@code
   * release.subject_denied} maps to {@link RelayReleaseError#SUBJECT_DENIED}; {@code
   * release.source_unavailable} maps to {@link RelayReleaseError#UNAVAILABLE}; an unparseable or
   * absent {@code code} maps to {@link RelayReleaseError#UNKNOWN}.
   */
  private RelayReleaseException mapError(String body) {
    String code = null;
    try {
      JsonNode root = objectMapper.readTree(body);
      code = textOrNull(root, "code");
    } catch (IOException | RuntimeException e) {
      // Unparseable problem document: fall through to UNKNOWN. Never log the raw body.
      log.warn("Relay error body could not be parsed; mapping to generic failure");
    }

    RelayReleaseError error = RelayReleaseError.fromCode(code);
    // SOURCE_UNAVAILABLE collapses into the UNAVAILABLE fail-closed outcome alongside transport.
    if (error == RelayReleaseError.SOURCE_UNAVAILABLE) {
      error = RelayReleaseError.UNAVAILABLE;
    }
    log.warn("Relay attribute release error mapped to {}", error);
    return new RelayReleaseException(error, code, null);
  }

  private static String textOrNull(JsonNode node, String field) {
    if (node == null) {
      return null;
    }
    JsonNode value = node.get(field);
    return value == null || value.isNull() ? null : value.asText();
  }

  /**
   * Converts a JSON object into a {@code Map<String,Object>} preserving scalar JSON types (string,
   * integer, floating point, boolean, null) and keeping nested objects/arrays as structured values.
   */
  private static Map<String, Object> toScalarMap(JsonNode node) {
    Map<String, Object> out = new LinkedHashMap<>();
    if (node == null || !node.isObject()) {
      return out;
    }
    Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
    while (fields.hasNext()) {
      Map.Entry<String, JsonNode> entry = fields.next();
      out.put(entry.getKey(), toJavaValue(entry.getValue()));
    }
    return out;
  }

  private static Object toJavaValue(JsonNode value) {
    if (value == null || value.isNull()) {
      return null;
    }
    if (value.isTextual()) {
      return value.textValue();
    }
    if (value.isBoolean()) {
      return value.booleanValue();
    }
    if (value.isInt() || value.isLong()) {
      return value.longValue();
    }
    if (value.isBigInteger()) {
      return value.bigIntegerValue();
    }
    if (value.isFloatingPointNumber()) {
      return value.doubleValue();
    }
    if (value.isArray()) {
      java.util.List<Object> list = new java.util.ArrayList<>();
      value.forEach(element -> list.add(toJavaValue(element)));
      return list;
    }
    if (value.isObject()) {
      return toScalarMap(value);
    }
    return value.asText();
  }
}
