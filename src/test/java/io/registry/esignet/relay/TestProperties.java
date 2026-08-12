package io.registry.esignet.relay;

import java.util.List;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Base64;

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
    relay.setResource("civil-person");
    relay.setLookup("by-uin");
    relay.setAccessProfile("esignet");
    relay.setAccept("application/json");
    relay.setDefaultClaims(
        List.of("individual_id", "name", "given_name", "family_name", "birthdate"));
    relay.setConnectTimeoutMs(2000);
    relay.setReadTimeoutMs(5000);

    RelayAuthenticatorProperties.Mint mint = props.getMint();
    mint.setTokenEndpoint("http://registry-mint:8080/token");
    mint.setClientId("esignet-relay-authenticator");
    mint.setPrivateJwk(TestRsaJwk.PRIVATE_JWK);
    mint.setAssertionLifetimeSeconds(120);
    mint.setTokenCacheMaxSeconds(300);
    mint.setConnectTimeoutMs(2000);
    mint.setReadTimeoutMs(1000);

    RelayAuthenticatorProperties.Esignet esignet = props.getEsignet();
    esignet.setSubjectIdType("uin");
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

  public static String mintPrivateJwk() {
    return TestRsaJwk.PRIVATE_JWK;
  }

  private static final class TestRsaJwk {
    private static final String PRIVATE_JWK = generate();

    private static String generate() {
      try {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        RSAPrivateCrtKey key = (RSAPrivateCrtKey) generator.generateKeyPair().getPrivate();
        return "{\"kty\":\"RSA\",\"alg\":\"RS256\",\"kid\":\"mint-client-test-key\""
            + ",\"n\":\"" + encoded(key.getModulus()) + "\""
            + ",\"e\":\"" + encoded(key.getPublicExponent()) + "\""
            + ",\"d\":\"" + encoded(key.getPrivateExponent()) + "\""
            + ",\"p\":\"" + encoded(key.getPrimeP()) + "\""
            + ",\"q\":\"" + encoded(key.getPrimeQ()) + "\""
            + ",\"dp\":\"" + encoded(key.getPrimeExponentP()) + "\""
            + ",\"dq\":\"" + encoded(key.getPrimeExponentQ()) + "\""
            + ",\"qi\":\"" + encoded(key.getCrtCoefficient()) + "\"}";
      } catch (Exception e) {
        throw new ExceptionInInitializerError(e);
      }
    }

    private static String encoded(java.math.BigInteger value) {
      byte[] bytes = value.toByteArray();
      int offset = bytes.length > 1 && bytes[0] == 0 ? 1 : 0;
      return Base64.getUrlEncoder().withoutPadding().encodeToString(
          java.util.Arrays.copyOfRange(bytes, offset, bytes.length));
    }
  }
}
