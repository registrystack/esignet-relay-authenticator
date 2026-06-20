package io.registry.esignet.relay.kyc;

import io.registry.esignet.relay.RelayAuthenticatorProperties;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Objects;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Loads the RSA signing key + X.509 certificate used to sign KYC/UserInfo payloads, and derives a
 * stable key id ({@code kid}) from the public key.
 *
 * <p>The signing material is loaded from a JDK {@link KeyStore} (PKCS12 or JKS) using the configured
 * path/passwords/alias. Pure JDK only — no BouncyCastle in main code. Tests inject an in-memory
 * {@link KeyStore} through the IDENTICAL {@link #KycSigningKeyService(KeyStore, String, String,
 * String)} constructor, so the signing mechanism is the same in tests and production.
 *
 * <p><b>kid scheme:</b> the {@code kid} is deterministic and derived solely from the RSA public key,
 * so the same key always yields the same {@code kid}. It is
 * {@code base64url(SHA-256(RFC 7638 JWK thumbprint canonical JSON))}, where the canonical JSON for an
 * RSA key is exactly <pre>{"e":"&lt;e&gt;","kty":"RSA","n":"&lt;n&gt;"}</pre> with {@code e} and
 * {@code n} base64url-encoded big-endian, minimal-length (no leading zero byte) integers, members in
 * lexicographic order and no whitespace (RFC 7638 §3.2). The same value is published as the JWS
 * header {@code kid} and as the certificate {@code keyId}.
 *
 * <p><b>Security:</b> never logs key material, passwords, or the private key. Only the non-sensitive
 * {@code kid} and algorithm may be logged.
 */
public class KycSigningKeyService {

  private static final Logger log = LoggerFactory.getLogger(KycSigningKeyService.class);

  /** Default JWS signing algorithm. */
  public static final String DEFAULT_ALGORITHM =
      RelayAuthenticatorProperties.Esignet.Kyc.Signing.DEFAULT_ALGORITHM;

  /** Minimum accepted RSA signing-key size, in bits. */
  static final int MIN_RSA_KEY_BITS = 2048;

  /** Supplies the loaded signing material on first use, so construction is tolerant. */
  private final Supplier<Material> materialSupplier;

  private volatile Material material;

  /**
   * Builds the service from an already-opened {@link KeyStore}. This is the single production loading
   * code path; tests feed an in-memory keystore here so the signing mechanism is identical. The
   * keystore is read eagerly so callers can rely on the resulting service.
   *
   * @param keyStore an opened keystore containing the signing entry
   * @param keyAlias the alias of the signing key entry
   * @param keyPassword the password protecting the private-key entry (may be {@code null} if none)
   * @param algorithm the JWS signing algorithm, for example {@code RS256}; defaults to
   *     {@code RS256} when blank
   * @throws IllegalStateException if the alias is absent, the key is not RSA, or the entry has no
   *     X.509 certificate
   */
  public KycSigningKeyService(
      KeyStore keyStore, String keyAlias, String keyPassword, String algorithm) {
    Material loaded = loadMaterial(keyStore, keyAlias, keyPassword, algorithm);
    this.material = loaded;
    this.materialSupplier = () -> loaded;
  }

  private KycSigningKeyService(Supplier<Material> materialSupplier) {
    this.materialSupplier = Objects.requireNonNull(materialSupplier, "materialSupplier");
  }

  /**
   * Builds a TOLERANT service that defers opening the keystore until the first signing/certificate
   * call. The Spring context loads even when keystore configuration is absent or invalid; only an
   * actual {@link #getPrivateKey()}/{@link #getCertificate()}/{@link #getKid()} call then fails with
   * a clear {@link IllegalStateException}. Loading uses the identical {@link #fromProperties}
   * mechanism.
   *
   * @param properties validated plugin configuration with {@code registry.esignet.kyc.signing.*}
   * @return a lazily-loading signing-key service
   */
  public static KycSigningKeyService lazyFromProperties(RelayAuthenticatorProperties properties) {
    Objects.requireNonNull(properties, "properties");
    return new KycSigningKeyService(() -> loadFromProperties(properties));
  }

  /**
   * Convenience factory that opens the keystore file described by the plugin configuration and builds
   * the service eagerly. Same loading mechanism as the keystore constructor.
   *
   * @param properties validated plugin configuration with {@code registry.esignet.kyc.signing.*}
   * @return a ready signing-key service
   * @throws IllegalStateException if the keystore cannot be opened or the entry cannot be loaded
   */
  public static KycSigningKeyService fromProperties(RelayAuthenticatorProperties properties) {
    Material loaded = loadFromProperties(properties);
    KycSigningKeyService service = new KycSigningKeyService(() -> loaded);
    service.material = loaded;
    return service;
  }

  private static Material loadFromProperties(RelayAuthenticatorProperties properties) {
    Objects.requireNonNull(properties, "properties");
    RelayAuthenticatorProperties.Esignet.Kyc.Signing signing =
        properties.getEsignet().getKyc().getSigning();
    String path = signing.getKeystorePath();
    if (path == null || path.isBlank()) {
      throw new IllegalStateException(
          "registry.esignet.kyc.signing.keystore-path must be set to load the signing key");
    }
    if (signing.getKeyAlias() == null || signing.getKeyAlias().isBlank()) {
      throw new IllegalStateException(
          "registry.esignet.kyc.signing.key-alias must be set to load the signing key");
    }
    KeyStore keyStore = openKeyStore(signing);
    return loadMaterial(
        keyStore, signing.getKeyAlias(), signing.getKeyPassword(), signing.getAlgorithm());
  }

  private Material material() {
    Material current = material;
    if (current == null) {
      synchronized (this) {
        current = material;
        if (current == null) {
          current = materialSupplier.get();
          material = current;
        }
      }
    }
    return current;
  }

  private static Material loadMaterial(
      KeyStore keyStore, String keyAlias, String keyPassword, String algorithm) {
    Objects.requireNonNull(keyStore, "keyStore");
    Objects.requireNonNull(keyAlias, "keyAlias");
    String alg = algorithm == null || algorithm.isBlank() ? DEFAULT_ALGORITHM : algorithm;

    PrivateKey loadedKey;
    Certificate loadedCert;
    try {
      char[] pwd = keyPassword == null ? new char[0] : keyPassword.toCharArray();
      loadedKey = (PrivateKey) keyStore.getKey(keyAlias, pwd);
      loadedCert = keyStore.getCertificate(keyAlias);
    } catch (Exception e) {
      // Do not include key material or passwords in the message.
      throw new IllegalStateException("Failed to load signing key entry from keystore", e);
    }
    if (loadedKey == null) {
      throw new IllegalStateException("No private key found for alias in keystore");
    }
    if (!(loadedKey instanceof RSAPrivateKey)) {
      throw new IllegalStateException("Signing key must be RSA");
    }
    if (!(loadedCert instanceof X509Certificate)) {
      throw new IllegalStateException("No X.509 certificate found for alias in keystore");
    }
    X509Certificate cert = (X509Certificate) loadedCert;
    if (!(cert.getPublicKey() instanceof RSAPublicKey)) {
      throw new IllegalStateException("Certificate public key must be RSA");
    }
    RSAPublicKey rsaPublicKey = (RSAPublicKey) cert.getPublicKey();
    int keyBits = rsaPublicKey.getModulus().bitLength();
    if (keyBits < MIN_RSA_KEY_BITS) {
      throw new IllegalStateException(
          "Signing RSA key must be at least " + MIN_RSA_KEY_BITS + " bits");
    }
    String kid = computeKid(rsaPublicKey);
    log.info("KYC signing key loaded (kid={}, alg={})", kid, alg);
    return new Material((RSAPrivateKey) loadedKey, cert, alg, kid);
  }

  private static KeyStore openKeyStore(RelayAuthenticatorProperties.Esignet.Kyc.Signing signing) {
    Path path = Path.of(signing.getKeystorePath());
    char[] storePwd =
        signing.getKeystorePassword() == null
            ? new char[0]
            : signing.getKeystorePassword().toCharArray();
    try (InputStream in = Files.newInputStream(path)) {
      KeyStore keyStore = KeyStore.getInstance(signing.getKeystoreType());
      keyStore.load(in, storePwd);
      return keyStore;
    } catch (Exception e) {
      // Path is not a secret; passwords/keys are never included.
      throw new IllegalStateException("Failed to open signing keystore", e);
    }
  }

  /**
   * Computes the stable {@code kid} from an RSA public key as
   * {@code base64url(SHA-256(RFC 7638 JWK thumbprint))}.
   */
  static String computeKid(RSAPublicKey publicKey) {
    String e = base64UrlUint(publicKey.getPublicExponent());
    String n = base64UrlUint(publicKey.getModulus());
    // RFC 7638 §3.2: required members in lexicographic order, no whitespace.
    String canonical = "{\"e\":\"" + e + "\",\"kty\":\"RSA\",\"n\":\"" + n + "\"}";
    try {
      MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
      byte[] digest = sha256.digest(canonical.getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    } catch (Exception ex) {
      // SHA-256 is mandated by the JCA spec; this should never happen.
      throw new IllegalStateException("SHA-256 not available", ex);
    }
  }

  /**
   * Base64url-encodes a positive {@link BigInteger} as the minimal-length big-endian octet sequence
   * (no sign byte, no leading zero), per the JWA {@code Base64urlUInt} encoding used by RFC 7638.
   */
  private static String base64UrlUint(BigInteger value) {
    byte[] bytes = value.toByteArray();
    // BigInteger.toByteArray() may prepend a 0x00 sign byte for positive values; strip it.
    if (bytes.length > 1 && bytes[0] == 0) {
      byte[] trimmed = new byte[bytes.length - 1];
      System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
      bytes = trimmed;
    }
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  /**
   * @return the stable key id published in the JWS header and the signing certificate
   * @throws IllegalStateException if the keystore cannot be loaded (lazy services)
   */
  public String getKid() {
    return material().kid();
  }

  /**
   * @return the RSA private key used to sign (never logged)
   * @throws IllegalStateException if the keystore cannot be loaded (lazy services)
   */
  public PrivateKey getPrivateKey() {
    return material().privateKey();
  }

  /**
   * @return the X.509 signing certificate
   * @throws IllegalStateException if the keystore cannot be loaded (lazy services)
   */
  public X509Certificate getCertificate() {
    return material().certificate();
  }

  /**
   * @return the JWS signing algorithm, for example {@code RS256}
   * @throws IllegalStateException if the keystore cannot be loaded (lazy services)
   */
  public String getAlgorithm() {
    return material().algorithm();
  }

  /** Immutable bundle of the loaded signing material. */
  private record Material(
      RSAPrivateKey privateKey, X509Certificate certificate, String algorithm, String kid) {}
}
