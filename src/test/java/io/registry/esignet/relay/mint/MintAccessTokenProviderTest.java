package io.registry.esignet.relay.mint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.registry.esignet.relay.RelayAuthenticatorProperties;
import io.registry.esignet.relay.TestProperties;
import io.registry.esignet.relay.relay.RelayStubServer;
import io.registry.esignet.relay.relay.RelayStubServer.StubResponse;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;

class MintAccessTokenProviderTest {

  @Test
  void cacheExpiresAtConfiguredMaximumBeforeReturnedLifetime() throws Exception {
    try (RelayStubServer stub = new RelayStubServer()) {
      RelayAuthenticatorProperties props = configured(stub);
      props.getMint().setTokenCacheMaxSeconds(10);
      MutableClock clock = new MutableClock(Instant.parse("2026-08-12T00:00:00Z"));
      MintAccessTokenProvider provider = provider(props, clock);

      close(provider.accessToken());
      clock.advanceSeconds(9);
      close(provider.accessToken());
      assertEquals(1, stub.mintRequests().size());
      clock.advanceSeconds(1);
      close(provider.accessToken());
      assertEquals(2, stub.mintRequests().size());
    }
  }

  @Test
  void cacheNeverOutlivesReturnedExpiresIn() throws Exception {
    try (RelayStubServer stub = new RelayStubServer()) {
      stub.setNextMintResponse(
          StubResponse.json(
              200,
              "{\"access_token\":\"short\",\"token_type\":\"Bearer\",\"expires_in\":5}"));
      RelayAuthenticatorProperties props = configured(stub);
      props.getMint().setTokenCacheMaxSeconds(300);
      MutableClock clock = new MutableClock(Instant.parse("2026-08-12T00:00:00Z"));
      MintAccessTokenProvider provider = provider(props, clock);

      close(provider.accessToken());
      clock.advanceSeconds(5);
      close(provider.accessToken());
      assertEquals(2, stub.mintRequests().size());
    }
  }

  @Test
  void concurrentMissesUseOneMintRequest() throws Exception {
    try (RelayStubServer stub = new RelayStubServer()) {
      stub.setNextMintResponse(
          new StubResponse(200, "application/json", RelayStubServer.MINT_SUCCESS_BODY, 100));
      RelayAuthenticatorProperties props = configured(stub);
      MintAccessTokenProvider provider = provider(props, Clock.systemUTC());
      ExecutorService executor = Executors.newFixedThreadPool(8);
      CountDownLatch start = new CountDownLatch(1);
      try {
        List<Future<?>> calls = new ArrayList<>();
        for (int index = 0; index < 8; index++) {
          calls.add(
              executor.submit(
                  () -> {
                    start.await();
                    close(provider.accessToken());
                    return null;
                  }));
        }
        start.countDown();
        for (Future<?> call : calls) call.get();
      } finally {
        executor.shutdownNow();
      }
      assertEquals(1, stub.mintRequests().size());
    }
  }

  private static RelayAuthenticatorProperties configured(RelayStubServer stub) {
    RelayAuthenticatorProperties props = TestProperties.valid();
    props.getMint().setTokenEndpoint(stub.mintTokenEndpoint());
    props.validate();
    return props;
  }

  private static MintAccessTokenProvider provider(
      RelayAuthenticatorProperties props, Clock clock) {
    return new MintAccessTokenProvider(props, HttpClient.newHttpClient(), new ObjectMapper(), clock);
  }

  private static void close(MintAccessTokenProvider.AccessToken token) {
    token.close();
  }

  private static final class MutableClock extends Clock {
    private Instant instant;

    private MutableClock(Instant instant) {
      this.instant = instant;
    }

    void advanceSeconds(long seconds) {
      instant = instant.plusSeconds(seconds);
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return instant;
    }
  }
}
