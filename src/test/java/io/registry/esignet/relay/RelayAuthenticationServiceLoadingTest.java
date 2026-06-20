package io.registry.esignet.relay;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.mosip.esignet.api.spi.Authenticator;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

/**
 * M0: the plugin is an {@link Authenticator} gated by the standard eSignet conditional property.
 */
class RelayAuthenticationServiceLoadingTest {

  @Test
  void implementsEsignetAuthenticator() {
    assertTrue(
        Authenticator.class.isAssignableFrom(RelayAuthenticationService.class),
        "RelayAuthenticationService must implement the eSignet Authenticator SPI");
  }

  @Test
  void gatedByStandardConditionalProperty() {
    ConditionalOnProperty condition =
        RelayAuthenticationService.class.getAnnotation(ConditionalOnProperty.class);
    assertNotNull(condition, "must be gated by @ConditionalOnProperty");
    assertArrayEquals(
        new String[] {"mosip.esignet.integration.authenticator"},
        condition.value(),
        "must be gated on the eSignet authenticator integration property");
    assertEquals(
        "RelayAuthenticationService",
        condition.havingValue(),
        "havingValue must match the documented bean name");
    assertEquals("RelayAuthenticationService", RelayAuthenticationService.BEAN_NAME);
  }
}
