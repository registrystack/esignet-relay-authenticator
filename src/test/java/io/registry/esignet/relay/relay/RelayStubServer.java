package io.registry.esignet.relay.relay;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Local Relay attribute-release stub for contract tests, built on the JDK {@link HttpServer} (no
 * WireMock). Follows {@code docs/relay-attribute-release-contract.md}.
 *
 * <p>Crucially, it returns the <b>same</b> {@code release.subject_denied} body for every collapsed
 * scenario (not-found, ambiguous, release-denied, required-claim-missing), so tests can prove the
 * plugin cannot and does not branch on the hidden sub-reason.
 */
public final class RelayStubServer implements AutoCloseable {

  /** The collapsed denial body, returned identically for all four internal scenarios. */
  public static final String SUBJECT_DENIED_BODY =
      "{\"type\":\"https://registry-relay.dev/problems/release/subject_denied\","
          + "\"title\":\"Subject release denied\",\"status\":403,"
          + "\"code\":\"release.subject_denied\"}";

  public static final String SUCCESS_BODY =
      "{"
          + "\"profile_id\":\"esignet-civil-userinfo\","
          + "\"profile_version\":\"v1\","
          + "\"claims\":{"
          + "\"individual_id\":\"NID-2001\","
          + "\"name\":\"Maria Santos\","
          + "\"given_name\":\"Maria\","
          + "\"family_name\":\"Santos\","
          + "\"birthdate\":\"1984-01-15\""
          + "},"
          + "\"source\":{"
          + "\"dataset\":\"civil_registry\","
          + "\"entity\":\"civil_person_detail\","
          + "\"subject_id_type\":\"national_id\","
          + "\"cardinality\":\"one\","
          + "\"checked_at\":\"2026-06-20T00:00:00Z\""
          + "}"
          + "}";

  /**
   * Success body with the {@code source} block gated off (profile not configured to include source
   * metadata). Proves the client tolerates an absent {@code source} without NPE.
   */
  public static final String SUCCESS_BODY_NO_SOURCE =
      "{"
          + "\"profile_id\":\"esignet-civil-userinfo\","
          + "\"profile_version\":\"v1\","
          + "\"claims\":{"
          + "\"individual_id\":\"NID-2001\""
          + "}"
          + "}";

  /** A response the stub should send. */
  public record StubResponse(int status, String contentType, String body, long delayMillis) {
    public static StubResponse json(int status, String body) {
      return new StubResponse(status, "application/json", body, 0);
    }

    public static StubResponse problem(int status, String body) {
      return new StubResponse(status, "application/problem+json", body, 0);
    }
  }

  /** Captures the headers and body the plugin sent, for header/contract assertions. */
  public static final class CapturedRequest {
    public final String method;
    public final String path;
    // Case-insensitive: the JDK HttpServer normalizes header-name capitalization on receipt.
    public final Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    public final String body;

    CapturedRequest(String method, String path, String body) {
      this.method = method;
      this.path = path;
      this.body = body;
    }
  }

  private final HttpServer server;
  private final List<CapturedRequest> requests = new CopyOnWriteArrayList<>();
  private volatile StubResponse nextResponse =
      StubResponse.json(200, SUCCESS_BODY);

  public RelayStubServer() throws IOException {
    this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    this.server.createContext("/", this::handle);
    this.server.start();
  }

  /** Sets the response the next request will receive. */
  public void setNextResponse(StubResponse response) {
    this.nextResponse = response;
  }

  public String baseUrl() {
    return "http://127.0.0.1:" + server.getAddress().getPort();
  }

  public List<CapturedRequest> requests() {
    return requests;
  }

  public CapturedRequest lastRequest() {
    return requests.get(requests.size() - 1);
  }

  private void handle(HttpExchange exchange) throws IOException {
    String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    CapturedRequest captured =
        new CapturedRequest(
            exchange.getRequestMethod(), exchange.getRequestURI().getPath(), body);
    exchange
        .getRequestHeaders()
        .forEach(
            (k, v) -> {
              if (!v.isEmpty()) {
                captured.headers.put(k, v.get(0));
              }
            });
    requests.add(captured);

    StubResponse response = this.nextResponse;
    if (response.delayMillis() > 0) {
      try {
        Thread.sleep(response.delayMillis());
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }

    byte[] payload = response.body() == null ? new byte[0] : response.body().getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", response.contentType());
    exchange.sendResponseHeaders(response.status(), payload.length == 0 ? -1 : payload.length);
    try (OutputStream os = exchange.getResponseBody()) {
      if (payload.length > 0) {
        os.write(payload);
      }
    }
  }

  @Override
  public void close() {
    server.stop(0);
  }
}
