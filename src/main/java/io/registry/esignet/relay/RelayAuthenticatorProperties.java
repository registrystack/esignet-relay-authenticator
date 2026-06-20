package io.registry.esignet.relay;

import jakarta.annotation.PostConstruct;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Typed configuration for the eSignet Relay Authenticator plugin.
 *
 * <p>Binds the {@code registry.relay.*} and {@code registry.esignet.*} property surface documented
 * in the plugin spec. Bound via Spring {@link ConfigurationProperties} (Spring is a provided
 * dependency at eSignet runtime). Groups are modelled as nested static classes.
 *
 * <p>Security-sensitive fields (Relay bearer token, KYC-token and PSUT HMAC secrets, keystore
 * passwords) are validated fail-fast by {@link #validate()} and are redacted from {@link #toString()}
 * and all logging. The token is ALWAYS transmitted as {@code Authorization: Bearer}; {@code
 * registry.relay.auth.credential-kind} is an operator label only and has no effect on the wire.
 */
@Component
@ConfigurationProperties(prefix = "registry")
public class RelayAuthenticatorProperties {

  /** Masking marker used wherever a configured secret would otherwise be printed. */
  public static final String REDACTED = "***REDACTED***";

  private Relay relay = new Relay();
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
    }

    Relay.AttributeRelease ar = relay.attributeRelease;
    if (isBlank(ar.profileId)) {
      problems.add("registry.relay.attribute-release.profile-id must be set");
    }
    if (isBlank(ar.profileVersion)) {
      problems.add("registry.relay.attribute-release.profile-version must be set");
    }
    if (isBlank(ar.pathTemplate)) {
      problems.add("registry.relay.attribute-release.path-template must be set");
    } else {
      if (!ar.pathTemplate.contains("{profile_id}")) {
        problems.add("registry.relay.attribute-release.path-template must contain {profile_id}");
      }
      if (!ar.pathTemplate.contains("{version}")) {
        problems.add("registry.relay.attribute-release.path-template must contain {version}");
      }
    }
    if (isBlank(ar.accept)) {
      problems.add("registry.relay.attribute-release.accept must be set");
    }

    if (isBlank(relay.subject.idType)) {
      problems.add("registry.relay.subject.id-type must be set");
    }

    if (relay.connectTimeoutMs <= 0) {
      problems.add("registry.relay.connect-timeout-ms must be a positive number of milliseconds");
    }
    if (relay.readTimeoutMs <= 0) {
      problems.add("registry.relay.read-timeout-ms must be a positive number of milliseconds");
    }

    // --- Security-sensitive: Relay bearer token (always Bearer on the wire) ---
    if (isBlank(relay.auth.bearerToken)) {
      problems.add("registry.relay.auth.bearer-token must be set (sent as Authorization: Bearer)");
    }

    // --- Security-sensitive: internal HMAC secrets ---
    if (isBlank(esignet.kycToken.hmacSecret)) {
      problems.add("registry.esignet.kyc-token.hmac-secret must be set");
    }
    if (esignet.kycToken.ttlSeconds <= 0) {
      problems.add("registry.esignet.kyc-token.ttl-seconds must be a positive number of seconds");
    }
    if (isBlank(esignet.psut.hmacSecret)) {
      problems.add("registry.esignet.psut.hmac-secret must be set");
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

  public Relay getRelay() {
    return relay;
  }

  public void setRelay(Relay relay) {
    this.relay = relay;
  }

  public Esignet getEsignet() {
    return esignet;
  }

  public void setEsignet(Esignet esignet) {
    this.esignet = esignet;
  }

  /**
   * Redacted view. Never prints the bearer token, HMAC secrets, or keystore passwords.
   *
   * @return a log-safe description of the configuration
   */
  @Override
  public String toString() {
    return "RelayAuthenticatorProperties{relay=" + relay + ", esignet=" + esignet + "}";
  }

  // ---------------------------------------------------------------------------
  // registry.relay.*
  // ---------------------------------------------------------------------------

  /** {@code registry.relay.*} group. */
  public static class Relay {
    private String baseUrl;
    private AttributeRelease attributeRelease = new AttributeRelease();
    private Subject subject = new Subject();
    private List<String> defaultClaims = Collections.emptyList();
    private int connectTimeoutMs = 2000;
    private int readTimeoutMs = 5000;
    private Auth auth = new Auth();

    public String getBaseUrl() {
      return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
      this.baseUrl = baseUrl;
    }

    public AttributeRelease getAttributeRelease() {
      return attributeRelease;
    }

    public void setAttributeRelease(AttributeRelease attributeRelease) {
      this.attributeRelease = attributeRelease;
    }

    public Subject getSubject() {
      return subject;
    }

    public void setSubject(Subject subject) {
      this.subject = subject;
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

    public Auth getAuth() {
      return auth;
    }

    public void setAuth(Auth auth) {
      this.auth = auth;
    }

    @Override
    public String toString() {
      return "Relay{baseUrl="
          + baseUrl
          + ", attributeRelease="
          + attributeRelease
          + ", subject="
          + subject
          + ", defaultClaims="
          + defaultClaims
          + ", connectTimeoutMs="
          + connectTimeoutMs
          + ", readTimeoutMs="
          + readTimeoutMs
          + ", auth="
          + auth
          + "}";
    }

    /** {@code registry.relay.attribute-release.*} group. */
    public static class AttributeRelease {
      private String profileId;
      private String profileVersion;
      private String pathTemplate =
          "/v1/attribute-releases/{profile_id}/versions/{version}/resolve";
      private String purpose;
      private String accept = "application/json";

      public String getProfileId() {
        return profileId;
      }

      public void setProfileId(String profileId) {
        this.profileId = profileId;
      }

      public String getProfileVersion() {
        return profileVersion;
      }

      public void setProfileVersion(String profileVersion) {
        this.profileVersion = profileVersion;
      }

      public String getPathTemplate() {
        return pathTemplate;
      }

      public void setPathTemplate(String pathTemplate) {
        this.pathTemplate = pathTemplate;
      }

      public String getPurpose() {
        return purpose;
      }

      public void setPurpose(String purpose) {
        this.purpose = purpose;
      }

      public String getAccept() {
        return accept;
      }

      public void setAccept(String accept) {
        this.accept = accept;
      }

      @Override
      public String toString() {
        return "AttributeRelease{profileId="
            + profileId
            + ", profileVersion="
            + profileVersion
            + ", pathTemplate="
            + pathTemplate
            + ", purpose="
            + purpose
            + ", accept="
            + accept
            + "}";
      }
    }

    /** {@code registry.relay.subject.*} group. */
    public static class Subject {
      private String idType;

      public String getIdType() {
        return idType;
      }

      public void setIdType(String idType) {
        this.idType = idType;
      }

      @Override
      public String toString() {
        return "Subject{idType=" + idType + "}";
      }
    }

    /**
     * {@code registry.relay.auth.*} group. {@code credentialKind} is a free-text operator label only
     * (for example {@code api_key} or {@code oidc_access_token}); the token is always sent as {@code
     * Authorization: Bearer} regardless of its value.
     */
    public static class Auth {
      private String credentialKind = "api_key";
      private String bearerToken;

      public String getCredentialKind() {
        return credentialKind;
      }

      public void setCredentialKind(String credentialKind) {
        this.credentialKind = credentialKind;
      }

      public String getBearerToken() {
        return bearerToken;
      }

      public void setBearerToken(String bearerToken) {
        this.bearerToken = bearerToken;
      }

      @Override
      public String toString() {
        return "Auth{credentialKind="
            + credentialKind
            + ", bearerToken="
            + (bearerToken == null ? "null" : REDACTED)
            + "}";
      }
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

    /**
     * Minimal claim list used as the account-check probe in {@code doKycAuth}. This proves the
     * subject exists/releasable WITHOUT fetching demographics before consent. Defaults to a single
     * {@code individual_id} claim (an identifier-echo profile choice for a trusted caller). Bound
     * from {@code registry.esignet.account-check-claims}.
     */
    private List<String> accountCheckClaims = List.of("individual_id");

    public Auth getAuth() {
      return auth;
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
          + ", kycToken="
          + kycToken
          + ", psut="
          + psut
          + ", kyc="
          + kyc
          + ", accountCheckClaims="
          + accountCheckClaims
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
       */
      public static class Signing {
        private String keystorePath;
        private String keystorePassword;
        private String keyAlias;
        private String keyPassword;

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
