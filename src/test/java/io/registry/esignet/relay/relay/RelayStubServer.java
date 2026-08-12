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

/** Local Registry Mint and Relay V2 stub for service and HTTP-contract tests. */
public final class RelayStubServer implements AutoCloseable {

  public static final String SUBJECT_DENIED_BODY =
      "{\"type\":\"https://id.registrystack.org/problems/registry-relay/consultation/unresolved\","
          + "\"title\":\"Requested record was not resolved\",\"status\":404,"
          + "\"code\":\"consultation.unresolved\"}";

  public static final String SUCCESS_BODY =
      "{\"data\":{"
          + "\"registryIdentifier\":\"civil-registry\","
          + "\"recordIdentifier\":\"opaque-record\","
          + "\"domainData\":{"
          + "\"individual_id\":\"NID-2001\","
          + "\"name\":\"Maria Santos\","
          + "\"given_name\":\"Maria\","
          + "\"family_name\":\"Santos\","
          + "\"birthdate\":\"1984-01-15\"}},"
          + "\"meta\":{\"accessProfile\":\"esignet\"}}";

  public static final String MINT_SUCCESS_BODY =
      "{\"access_token\":\"mint-issued-relay-token\",\"token_type\":\"Bearer\",\"expires_in\":300}";

  public record StubResponse(int status, String contentType, String body, long delayMillis) {
    public static StubResponse json(int status, String body) {
      return new StubResponse(status, "application/json", body, 0);
    }

    public static StubResponse problem(int status, String body) {
      return new StubResponse(status, "application/problem+json", body, 0);
    }
  }

  public static final class CapturedRequest {
    public final String method;
    public final String path;
    public final String query;
    public final Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    public final String body;

    CapturedRequest(String method, String path, String query, String body) {
      this.method = method;
      this.path = path;
      this.query = query;
      this.body = body;
    }
  }

  private final HttpServer server;
  private final List<CapturedRequest> relayRequests = new CopyOnWriteArrayList<>();
  private final List<CapturedRequest> mintRequests = new CopyOnWriteArrayList<>();
  private volatile StubResponse nextRelayResponse = StubResponse.json(200, SUCCESS_BODY);
  private volatile StubResponse nextMintResponse = StubResponse.json(200, MINT_SUCCESS_BODY);

  public RelayStubServer() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/", this::handle);
    server.start();
  }

  public void setNextResponse(StubResponse response) {
    nextRelayResponse = response;
  }

  public void setNextMintResponse(StubResponse response) {
    nextMintResponse = response;
  }

  public String baseUrl() {
    return "http://127.0.0.1:" + server.getAddress().getPort();
  }

  public String mintTokenEndpoint() {
    return baseUrl() + "/token";
  }

  public List<CapturedRequest> requests() {
    return relayRequests;
  }

  public List<CapturedRequest> mintRequests() {
    return mintRequests;
  }

  public CapturedRequest lastRequest() {
    return relayRequests.get(relayRequests.size() - 1);
  }

  private void handle(HttpExchange exchange) throws IOException {
    String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    CapturedRequest captured =
        new CapturedRequest(
            exchange.getRequestMethod(),
            exchange.getRequestURI().getPath(),
            exchange.getRequestURI().getRawQuery(),
            body);
    exchange.getRequestHeaders().forEach((key, values) -> {
      if (!values.isEmpty()) captured.headers.put(key, values.get(0));
    });

    boolean mint = "/token".equals(captured.path);
    (mint ? mintRequests : relayRequests).add(captured);
    StubResponse response = mint ? nextMintResponse : nextRelayResponse;
    if (response.delayMillis() > 0) {
      try {
        Thread.sleep(response.delayMillis());
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }
    byte[] payload =
        response.body() == null ? new byte[0] : response.body().getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", response.contentType());
    exchange.sendResponseHeaders(response.status(), payload.length == 0 ? -1 : payload.length);
    try (OutputStream output = exchange.getResponseBody()) {
      if (payload.length > 0) output.write(payload);
    }
  }

  @Override
  public void close() {
    server.stop(0);
  }
}
