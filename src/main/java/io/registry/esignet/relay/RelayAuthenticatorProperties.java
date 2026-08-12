package io.registry.esignet.relay;

import jakarta.annotation.PostConstruct;
import io.registry.esignet.relay.mint.MintClientAssertionSigner;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Typed configuration for the eSignet Relay Authenticator plugin.
 *
 * <p>Binds the {@code registry.relay.*}, {@code registry.mint.*}, and {@code registry.esignet.*}
 * property surface documented in the plugin spec.
 *
 * <p>Gated by the same {@link ConditionalOnProperty} as the authenticator and its collaborator graph
 * ({@code mosip.esignet.integration.authenticator=RelayAuthenticationService}), so in a deployment
 * that selects a different authenticator this bean is never created and its fail-fast
 * {@link #validate()} never runs — the plugin stays fully dormant rather than rejecting an unrelated
 * eSignet configuration at startup.
 *
 * <p>Security-sensitive fields (the Mint client private JWK, KYC-token and PSUT HMAC secrets, and
 * keystore passwords) are validated fail-fast and redacted from {@link #toString()} and all logging.
 */
@Component
@ConfigurationProperties(prefix = "registry")
@ConditionalOnProperty(
    value = "mosip.esignet.integration.authenticator",
    havingValue = RelayAuthenticationService.BEAN_NAME)
public class RelayAuthenticatorProperties {

  /** Masking marker used wherever a configured secret would otherwise be printed. */
  public static final String REDACTED = "***REDACTED***";

  /**
   * Minimum length (characters) required for the HS256 KYC-token and PSUT HMAC secrets. These secrets
   * key the token signature and the PSUT derivation directly, so a short/low-entropy value would be
   * brute-forceable; 32 characters is a conservative floor for a 256-bit MAC.
   */
  static final int MIN_HMAC_SECRET_LENGTH = 32;

  private static final Logger log = LoggerFactory.getLogger(RelayAuthenticatorProperties.class);

  private Relay relay = new Relay();
  private Mint mint = new Mint();
  private Esignet esignet = new Esignet();

  /**
   * Fail-fast validation invoked at bean initialization. Collects every problem and throws a single
   * {@link RelayAuthenticatorConfigException} listing all missing/invalid fields, so an operator can
   * fix the configuration in one pass rather than chasing errors one at a time.
   *
   * @throws RelayAuthenticatorConfigException if any required or security-sensitive field is missing
   *     or invalid
   */
  @PostConstruct
  public void validate() {
    List<String> problems = new ArrayList<>();

    // --- Relay endpoint ---
    if (isBlank(relay.baseUrl)) {
      problems.add("registry.relay.base-url must be set");
    } else if (!isAbsoluteHttpUrl(relay.baseUrl)) {
      problems.add("registry.relay.base-url must be a valid absolute http(s) URL");
    } else {
      warnIfPlaintextNonLoopback(relay.baseUrl);
    }

    if (isBlank(relay.resource)) {
      problems.add("registry.relay.resource must be set");
    }
    if (isBlank(relay.lookup)) {
      problems.add("registry.relay.lookup must be set");
    }
    if (isBlank(relay.accept)) {
      problems.add("registry.relay.accept must be set");
    }
    if (relay.defaultClaims == null || relay.defaultClaims.isEmpty()) {
      problems.add("registry.relay.default-claims must name the provisioned Relay properties");
    } else if (relay.defaultClaims.stream()
        .anyMatch(RelayAuthenticatorProperties::invalidFieldName)) {
      problems.add("registry.relay.default-claims contains an invalid Relay property name");
    }

    if (relay.connectTimeoutMs <= 0) {
      problems.add("registry.relay.connect-timeout-ms must be a positive number of milliseconds");
    }
    if (relay.readTimeoutMs <= 0) {
      problems.add("registry.relay.read-timeout-ms must be a positive number of milliseconds");
    }

    // --- Registry Mint private-key-JWT client credentials ---
    if (isBlank(mint.tokenEndpoint)) {
      problems.add("registry.mint.token-endpoint must be set");
    } else if (!isAbsoluteHttpUrl(mint.tokenEndpoint)) {
      problems.add("registry.mint.token-endpoint must be a valid absolute http(s) URL");
    } else {
      warnIfPlaintextNonLoopback(mint.tokenEndpoint);
    }
    if (isBlank(mint.clientId)) {
      problems.add("registry.mint.client-id must be set");
    }
    if (isBlank(mint.privateJwk)) {
      problems.add("registry.mint.private-jwk must be set");
    } else {
      try {
        MintClientAssertionSigner.validatePrivateJwk(mint.privateJwk);
      } catch (IllegalArgumentException e) {
        problems.add("registry.mint.private-jwk must be a valid private RS256 JWK with kid");
      }
    }
    if (mint.assertionLifetimeSeconds < 1 || mint.assertionLifetimeSeconds > 300) {
      problems.add("registry.mint.assertion-lifetime-seconds must be between 1 and 300");
    }
    if (mint.tokenCacheMaxSeconds < 1 || mint.tokenCacheMaxSeconds > 3600) {
      problems.add("registry.mint.token-cache-max-seconds must be between 1 and 3600");
    }
    if (mint.connectTimeoutMs <= 0) {
      problems.add("registry.mint.connect-timeout-ms must be positive");
    }
    if (mint.readTimeoutMs <= 0) {
      problems.add("registry.mint.read-timeout-ms must be positive");
    }

    if (isBlank(esignet.subjectIdType)) {
      problems.add("registry.esignet.subject-id-type must be set");
    }
    if (esignet.accountCheckClaims == null
        || esignet.accountCheckClaims.isEmpty()
        || esignet.accountCheckClaims.stream()
            .anyMatch(claim -> !relay.defaultClaims.contains(claim))) {
      problems.add(
          "registry.esignet.account-check-claims must be a non-empty subset of"
              + " registry.relay.default-claims");
    }

    // --- Security-sensitive: internal HMAC secrets ---
    // These key the HS256 KYC token and the PSUT derivation directly, so a short/low-entropy value is
    // brute-forceable; require a non-trivial minimum length in addition to non-blank.
    if (isBlank(esignet.kycToken.hmacSecret)) {
      problems.add("registry.esignet.kyc-token.hmac-secret must be set");
    } else if (esignet.kycToken.hmacSecret.length() < MIN_HMAC_SECRET_LENGTH) {
      problems.add(
          "registry.esignet.kyc-token.hmac-secret must be at least "
              + MIN_HMAC_SECRET_LENGTH
              + " characters");
    }
    if (esignet.kycToken.ttlSeconds <= 0) {
      problems.add("registry.esignet.kyc-token.ttl-seconds must be a positive number of seconds");
    }
    if (isBlank(esignet.psut.hmacSecret)) {
      problems.add("registry.esignet.psut.hmac-secret must be set");
    } else if (esignet.psut.hmacSecret.length() < MIN_HMAC_SECRET_LENGTH) {
      problems.add(
          "registry.esignet.psut.hmac-secret must be at least "
              + MIN_HMAC_SECRET_LENGTH
              + " characters");
    }
    // The two HMAC secrets MUST be distinct. They key independent security domains (the KYC-token
    // signature vs the PSUT derivation); sharing one key would let a single compromise undermine both
    // and couple the token and the partner-specific subject. Only compare when both are present so
    // this does not mask the missing-secret problems reported above.
    if (!isBlank(esignet.kycToken.hmacSecret)
        && !isBlank(esignet.psut.hmacSecret)
        && esignet.kycToken.hmacSecret.equals(esignet.psut.hmacSecret)) {
      problems.add(
          "registry.esignet.kyc-token.hmac-secret and registry.esignet.psut.hmac-secret must differ");
    }

    // --- Security-sensitive: signing keystore, required only for self-contained-jws ---
    if (Esignet.Kyc.RESPONSE_MODE_SELF_CONTAINED_JWS.equals(esignet.kyc.responseMode)) {
      Esignet.Kyc.Signing s = esignet.kyc.signing;
      if (isBlank(s.keystorePath)) {
        problems.add(
            "registry.esignet.kyc.signing.keystore-path must be set for"
                + " response-mode=self-contained-jws");
      }
      if (isBlank(s.keyAlias)) {
        problems.add(
            "registry.esignet.kyc.signing.key-alias must be set for"
                + " response-mode=self-contained-jws");
      }
      if (isBlank(s.keystorePassword)) {
        problems.add(
            "registry.esignet.kyc.signing.keystore-password must be set for"
                + " response-mode=self-contained-jws");
      }
      if (isBlank(s.keyPassword)) {
        problems.add(
            "registry.esignet.kyc.signing.key-password must be set for"
                + " response-mode=self-contained-jws");
      }
    }

    if (!problems.isEmpty()) {
      throw new RelayAuthenticatorConfigException(problems);
    }
  }

  private static boolean isBlank(String s) {
    return s == null || s.isBlank();
  }

  private static boolean invalidFieldName(String value) {
    return isBlank(value) || !value.matches("[A-Za-z][A-Za-z0-9_.-]*");
  }

  private static boolean isAbsoluteHttpUrl(String value) {
    try {
      URI uri = new URI(value.trim());
      if (!uri.isAbsolute() || uri.getScheme() == null) {
        return false;
      }
      String scheme = uri.getScheme().toLowerCase();
      return (scheme.equals("http") || scheme.equals("https")) && uri.getHost() != null;
    } catch (URISyntaxException e) {
      return false;
    }
  }

  /**
   * Warns when the Relay base URL is plaintext {@code http} to a non-loopback host: the Bearer token
   * and subject identifiers would travel unencrypted. Loopback ({@code localhost}/{@code 127.0.0.0/8}/
   * {@code ::1}) is allowed silently for local development. Only the host is logged, never credentials.
   */
  private static void warnIfPlaintextNonLoopback(String baseUrl) {
    try {
      URI uri = new URI(baseUrl.trim());
      if ("http".equalsIgnoreCase(uri.getScheme()) && !isLoopbackHost(uri.getHost())) {
        log.warn("A Registry service endpoint uses plaintext http; production requires https");
      }
    } catch (URISyntaxException e) {
      // Already validated as an absolute http(s) URL above; nothing to warn about.
    }
  }

  private static boolean isLoopbackHost(String host) {
    if (host == null) {
      return false;
    }
    String h = host.toLowerCase();
    return h.equals("localhost") || h.equals("::1") || h.equals("[::1]") || h.startsWith("127.");
  }

  public Relay getRelay() {
    return relay;
  }

  public void setRelay(Relay relay) {
    this.relay = relay;
  }

  public Mint getMint() {
    return mint;
  }

  public void setMint(Mint mint) {
    this.mint = mint;
  }

  public Esignet getEsignet() {
    return esignet;
  }

  public void setEsignet(Esignet esignet) {
    this.esignet = esignet;
  }

  /**
   * Redacted view. Never prints private key material, HMAC secrets, or keystore passwords.
   *
   * @return a log-safe description of the configuration
   */
  @Override
  public String toString() {
    return "RelayAuthenticatorProperties{relay="
        + relay
        + ", mint="
        + mint
        + ", esignet="
        + esignet
        + "}";
  }

  // ---------------------------------------------------------------------------
  // registry.relay.*
  // ---------------------------------------------------------------------------

  /** {@code registry.relay.*} group. */
  public static class Relay {
    private String baseUrl;
    private String resource;
    private String lookup;
    private String accessProfile;
    private String accept = "application/json";
    private List<String> defaultClaims = Collections.emptyList();
    private int connectTimeoutMs = 2000;
    private int readTimeoutMs = 5000;

    public String getBaseUrl() {
      return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
      this.baseUrl = baseUrl;
    }

    public String getResource() {
      return resource;
    }

    public void setResource(String resource) {
      this.resource = resource;
    }

    public String getLookup() {
      return lookup;
    }

    public void setLookup(String lookup) {
      this.lookup = lookup;
    }

    public String getAccessProfile() {
      return accessProfile;
    }

    public void setAccessProfile(String accessProfile) {
      this.accessProfile = accessProfile;
    }

    public String getAccept() {
      return accept;
    }

    public void setAccept(String accept) {
      this.accept = accept;
    }

    public List<String> getDefaultClaims() {
      return defaultClaims;
    }

    public void setDefaultClaims(List<String> defaultClaims) {
      this.defaultClaims = defaultClaims == null ? Collections.emptyList() : defaultClaims;
    }

    public int getConnectTimeoutMs() {
      return connectTimeoutMs;
    }

    public void setConnectTimeoutMs(int connectTimeoutMs) {
      this.connectTimeoutMs = connectTimeoutMs;
    }

    public int getReadTimeoutMs() {
      return readTimeoutMs;
    }

    public void setReadTimeoutMs(int readTimeoutMs) {
      this.readTimeoutMs = readTimeoutMs;
    }

    @Override
    public String toString() {
      return "Relay{baseUrl="
          + baseUrl
          + ", resource="
          + resource
          + ", lookup="
          + lookup
          + ", accessProfile="
          + accessProfile
          + ", accept="
          + accept
          + ", defaultClaims="
          + defaultClaims
          + ", connectTimeoutMs="
          + connectTimeoutMs
          + ", readTimeoutMs="
          + readTimeoutMs
          + "}";
    }
  }

  /** {@code registry.mint.*} OAuth client-credentials group. */
  public static class Mint {
    private String tokenEndpoint;
    private String clientId;
    private String privateJwk;
    private int assertionLifetimeSeconds = 120;
    private int tokenCacheMaxSeconds = 300;
    private int connectTimeoutMs = 2000;
    private int readTimeoutMs = 5000;

    public String getTokenEndpoint() {
      return tokenEndpoint;
    }

    public void setTokenEndpoint(String tokenEndpoint) {
      this.tokenEndpoint = tokenEndpoint;
    }

    public String getClientId() {
      return clientId;
    }

    public void setClientId(String clientId) {
      this.clientId = clientId;
    }

    public String getPrivateJwk() {
      return privateJwk;
    }

    public void setPrivateJwk(String privateJwk) {
      this.privateJwk = privateJwk;
    }

    public int getAssertionLifetimeSeconds() {
      return assertionLifetimeSeconds;
    }

    public void setAssertionLifetimeSeconds(int value) {
      this.assertionLifetimeSeconds = value;
    }

    public int getTokenCacheMaxSeconds() {
      return tokenCacheMaxSeconds;
    }

    public void setTokenCacheMaxSeconds(int value) {
      this.tokenCacheMaxSeconds = value;
    }

    public int getConnectTimeoutMs() {
      return connectTimeoutMs;
    }

    public void setConnectTimeoutMs(int value) {
      this.connectTimeoutMs = value;
    }

    public int getReadTimeoutMs() {
      return readTimeoutMs;
    }

    public void setReadTimeoutMs(int value) {
      this.readTimeoutMs = value;
    }

    @Override
    public String toString() {
      return "Mint{tokenEndpoint="
          + tokenEndpoint
          + ", clientId="
          + clientId
          + ", privateJwk="
          + (privateJwk == null ? "null" : REDACTED)
          + ", assertionLifetimeSeconds="
          + assertionLifetimeSeconds
          + ", tokenCacheMaxSeconds="
          + tokenCacheMaxSeconds
          + ", connectTimeoutMs="
          + connectTimeoutMs
          + ", readTimeoutMs="
          + readTimeoutMs
          + "}";
    }
  }

  // ---------------------------------------------------------------------------
  // registry.esignet.*
  // ---------------------------------------------------------------------------

  /** {@code registry.esignet.*} group. */
  public static class Esignet {
    private Auth auth = new Auth();
    private KycToken kycToken = new KycToken();
    private Psut psut = new Psut();
    private Kyc kyc = new Kyc();
    private String subjectIdType = "uin";

    /**
     * Minimal claim list used as the account-check probe in {@code doKycAuth}. This proves the
     * subject exists/releasable WITHOUT fetching demographics before consent. Defaults to a single
     * {@code individual_id} claim (an identifier-echo profile choice for a trusted caller). Bound
     * from {@code registry.esignet.account-check-claims}.
     */
    private List<String> accountCheckClaims = List.of("individual_id");

    /**
     * eSignet/OIDC UserInfo claim name -&gt; Relay source token. Bound from
     * {@code registry.esignet.claim-map.*}. Dotted keys such as {@code address.region} bind via
     * {@code registry.esignet.claim-map[address.region]}. The reserved source token {@code $psut}
     * marks a protocol-derived claim (the partner-specific subject) that is populated locally and
     * NEVER requested from Relay. Defaults to the spec example mapping when unset.
     */
    private Map<String, String> claimMap = defaultClaimMap();

    private static Map<String, String> defaultClaimMap() {
      Map<String, String> map = new LinkedHashMap<>();
      map.put("sub", "$psut");
      map.put("individual_id", "individual_id");
      map.put("name", "name");
      map.put("given_name", "given_name");
      map.put("family_name", "family_name");
      map.put("birthdate", "birthdate");
      map.put("gender", "gender");
      map.put("address.region", "address.region");
      return Collections.unmodifiableMap(map);
    }

    public Auth getAuth() {
      return auth;
    }

    public String getSubjectIdType() {
      return subjectIdType;
    }

    public void setSubjectIdType(String subjectIdType) {
      this.subjectIdType = subjectIdType;
    }

    public void setAuth(Auth auth) {
      this.auth = auth;
    }

    public List<String> getAccountCheckClaims() {
      return accountCheckClaims;
    }

    public void setAccountCheckClaims(List<String> accountCheckClaims) {
      this.accountCheckClaims =
          accountCheckClaims == null || accountCheckClaims.isEmpty()
              ? List.of("individual_id")
              : accountCheckClaims;
    }

    public Map<String, String> getClaimMap() {
      return claimMap;
    }

    public void setClaimMap(Map<String, String> claimMap) {
      // Empty map means "no mapping" (the operator explicitly cleared it); only null falls back
      // to the spec default so an unset binding still ships a sensible mapping.
      this.claimMap = claimMap == null ? defaultClaimMap() : claimMap;
    }

    public KycToken getKycToken() {
      return kycToken;
    }

    public void setKycToken(KycToken kycToken) {
      this.kycToken = kycToken;
    }

    public Psut getPsut() {
      return psut;
    }

    public void setPsut(Psut psut) {
      this.psut = psut;
    }

    public Kyc getKyc() {
      return kyc;
    }

    public void setKyc(Kyc kyc) {
      this.kyc = kyc;
    }

    @Override
    public String toString() {
      return "Esignet{auth="
          + auth
          + ", subjectIdType="
          + subjectIdType
          + ", kycToken="
          + kycToken
          + ", psut="
          + psut
          + ", kyc="
          + kyc
          + ", accountCheckClaims="
          + accountCheckClaims
          + ", claimMap="
          + claimMap
          + "}";
    }

    /** {@code registry.esignet.auth.*} group, including the nested OTP settings. */
    public static class Auth {
      private List<String> supportedFactors = Collections.emptyList();
      private Otp otp = new Otp();

      public List<String> getSupportedFactors() {
        return supportedFactors;
      }

      public void setSupportedFactors(List<String> supportedFactors) {
        this.supportedFactors =
            supportedFactors == null ? Collections.emptyList() : supportedFactors;
      }

      public Otp getOtp() {
        return otp;
      }

      public void setOtp(Otp otp) {
        this.otp = otp;
      }

      @Override
      public String toString() {
        return "Auth{supportedFactors=" + supportedFactors + ", otp=" + otp + "}";
      }

      /**
       * {@code registry.esignet.auth.otp.*} group. The static OTP value is treated as a secret and
       * is redacted from logging.
       */
      public static class Otp {
        private List<String> channels = Collections.emptyList();
        private String mode = "static";
        private String staticValue;
        private boolean staticEnabled = false;

        public List<String> getChannels() {
          return channels;
        }

        public void setChannels(List<String> channels) {
          this.channels = channels == null ? Collections.emptyList() : channels;
        }

        public String getMode() {
          return mode;
        }

        public void setMode(String mode) {
          this.mode = mode;
        }

        public String getStaticValue() {
          return staticValue;
        }

        public void setStaticValue(String staticValue) {
          this.staticValue = staticValue;
        }

        public boolean isStaticEnabled() {
          return staticEnabled;
        }

        public void setStaticEnabled(boolean staticEnabled) {
          this.staticEnabled = staticEnabled;
        }

        @Override
        public String toString() {
          return "Otp{channels="
              + channels
              + ", mode="
              + mode
              + ", staticValue="
              + (staticValue == null ? "null" : REDACTED)
              + ", staticEnabled="
              + staticEnabled
              + "}";
        }
      }
    }

    /** {@code registry.esignet.kyc-token.*} group. The HMAC secret is redacted from logging. */
    public static class KycToken {
      private String hmacSecret;
      private int ttlSeconds = 300;

      public String getHmacSecret() {
        return hmacSecret;
      }

      public void setHmacSecret(String hmacSecret) {
        this.hmacSecret = hmacSecret;
      }

      public int getTtlSeconds() {
        return ttlSeconds;
      }

      public void setTtlSeconds(int ttlSeconds) {
        this.ttlSeconds = ttlSeconds;
      }

      @Override
      public String toString() {
        return "KycToken{hmacSecret="
            + (hmacSecret == null ? "null" : REDACTED)
            + ", ttlSeconds="
            + ttlSeconds
            + "}";
      }
    }

    /** {@code registry.esignet.psut.*} group. The HMAC secret is redacted from logging. */
    public static class Psut {
      private String hmacSecret;

      public String getHmacSecret() {
        return hmacSecret;
      }

      public void setHmacSecret(String hmacSecret) {
        this.hmacSecret = hmacSecret;
      }

      @Override
      public String toString() {
        return "Psut{hmacSecret=" + (hmacSecret == null ? "null" : REDACTED) + "}";
      }
    }

    /** {@code registry.esignet.kyc.*} group, including the nested signing keystore settings. */
    public static class Kyc {
      /** Response mode that requires a local signing keystore. */
      public static final String RESPONSE_MODE_SELF_CONTAINED_JWS = "self-contained-jws";

      private String responseMode = RESPONSE_MODE_SELF_CONTAINED_JWS;
      private Signing signing = new Signing();

      public String getResponseMode() {
        return responseMode;
      }

      public void setResponseMode(String responseMode) {
        this.responseMode = responseMode;
      }

      public Signing getSigning() {
        return signing;
      }

      public void setSigning(Signing signing) {
        this.signing = signing;
      }

      @Override
      public String toString() {
        return "Kyc{responseMode=" + responseMode + ", signing=" + signing + "}";
      }

      /**
       * {@code registry.esignet.kyc.signing.*} group. Keystore and key passwords are redacted from
       * logging.
       *
       * <p>{@code algorithm} is the JWS signing algorithm (default {@code RS256}); it is published in
       * the JWS header and must match the algorithm reported alongside the signing certificate.
       * {@code keystoreType} is the JDK {@link java.security.KeyStore} type used to open the keystore
       * file (default {@code PKCS12}; {@code JKS} is also supported).
       */
      public static class Signing {
        /** Default JWS signing algorithm. */
        public static final String DEFAULT_ALGORITHM = "RS256";

        /** Default keystore type. */
        public static final String DEFAULT_KEYSTORE_TYPE = "PKCS12";

        private String keystorePath;
        private String keystorePassword;
        private String keyAlias;
        private String keyPassword;
        private String algorithm = DEFAULT_ALGORITHM;
        private String keystoreType = DEFAULT_KEYSTORE_TYPE;

        public String getKeystorePath() {
          return keystorePath;
        }

        public void setKeystorePath(String keystorePath) {
          this.keystorePath = keystorePath;
        }

        public String getKeystorePassword() {
          return keystorePassword;
        }

        public void setKeystorePassword(String keystorePassword) {
          this.keystorePassword = keystorePassword;
        }

        public String getKeyAlias() {
          return keyAlias;
        }

        public void setKeyAlias(String keyAlias) {
          this.keyAlias = keyAlias;
        }

        public String getKeyPassword() {
          return keyPassword;
        }

        public void setKeyPassword(String keyPassword) {
          this.keyPassword = keyPassword;
        }

        public String getAlgorithm() {
          return algorithm;
        }

        public void setAlgorithm(String algorithm) {
          this.algorithm =
              algorithm == null || algorithm.isBlank() ? DEFAULT_ALGORITHM : algorithm;
        }

        public String getKeystoreType() {
          return keystoreType;
        }

        public void setKeystoreType(String keystoreType) {
          this.keystoreType =
              keystoreType == null || keystoreType.isBlank() ? DEFAULT_KEYSTORE_TYPE : keystoreType;
        }

        @Override
        public String toString() {
          return "Signing{keystorePath="
              + keystorePath
              + ", keystorePassword="
              + (keystorePassword == null ? "null" : REDACTED)
              + ", keyAlias="
              + keyAlias
              + ", keyPassword="
              + (keyPassword == null ? "null" : REDACTED)
              + ", algorithm="
              + algorithm
              + ", keystoreType="
              + keystoreType
              + "}";
        }
      }
    }
  }

  /**
   * Convenience for tests and callers binding from a comma-separated string. Not used by Spring
   * binding (which already handles lists), but handy when constructing the holder by hand.
   *
   * @param csv comma-separated values, may be {@code null}
   * @return an immutable list of trimmed, non-empty tokens
   */
  public static List<String> splitCsv(String csv) {
    if (csv == null || csv.isBlank()) {
      return Collections.emptyList();
    }
    List<String> out = new ArrayList<>();
    for (String token : Arrays.asList(csv.split(","))) {
      String trimmed = token.trim();
      if (!trimmed.isEmpty()) {
        out.add(trimmed);
      }
    }
    return Collections.unmodifiableList(out);
  }
}
