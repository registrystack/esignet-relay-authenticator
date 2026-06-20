package io.registry.esignet.relay;

import java.util.List;

/**
 * Builds fully-populated, valid {@link RelayAuthenticatorProperties} for tests. Individual tests
 * mutate one field to drive validation/behavior scenarios.
 */
public final class TestProperties {

  private TestProperties() {}

  /** A complete, valid configuration that passes {@link RelayAuthenticatorProperties#validate()}. */
  public static RelayAuthenticatorProperties valid() {
    RelayAuthenticatorProperties props = new RelayAuthenticatorProperties();

    RelayAuthenticatorProperties.Relay relay = props.getRelay();
    relay.setBaseUrl("http://registry-relay:8080");
    relay.getAttributeRelease().setProfileId("esignet-civil-userinfo");
    relay.getAttributeRelease().setProfileVersion("v1");
    relay
        .getAttributeRelease()
        .setPathTemplate("/v1/attribute-releases/{profile_id}/versions/{version}/resolve");
    relay
        .getAttributeRelease()
        .setPurpose("https://demo.example.gov/purpose/esignet-identity-verification");
    relay.getAttributeRelease().setAccept("application/json");
    relay.getSubject().setIdType("national_id");
    relay.setDefaultClaims(
        List.of("individual_id", "name", "given_name", "family_name", "birthdate"));
    relay.setConnectTimeoutMs(2000);
    relay.setReadTimeoutMs(5000);
    relay.getAuth().setCredentialKind("api_key");
    relay.getAuth().setBearerToken("relay-test-token");

    RelayAuthenticatorProperties.Esignet esignet = props.getEsignet();
    esignet.getAuth().setSupportedFactors(List.of("OTP"));
    esignet.getAuth().getOtp().setChannels(List.of("email", "phone"));
    esignet.getAuth().getOtp().setMode("static");
    esignet.getAuth().getOtp().setStaticValue("111111");
    esignet.getAuth().getOtp().setStaticEnabled(false);
    // HMAC secrets must be at least RelayAuthenticatorProperties.MIN_HMAC_SECRET_LENGTH chars.
    esignet.getKycToken().setHmacSecret("kyc-token-hmac-secret-0123456789abcdef");
    esignet.getKycToken().setTtlSeconds(300);
    esignet.getPsut().setHmacSecret("psut-hmac-secret-0123456789abcdef0123");

    // Default response mode is self-contained-jws, so signing keystore settings are required.
    esignet.getKyc().setResponseMode("self-contained-jws");
    esignet.getKyc().getSigning().setKeystorePath("/etc/secrets/kyc-keystore.p12");
    esignet.getKyc().getSigning().setKeystorePassword("keystore-pass");
    esignet.getKyc().getSigning().setKeyAlias("kyc-signing");
    esignet.getKyc().getSigning().setKeyPassword("key-pass");

    return props;
  }
}
