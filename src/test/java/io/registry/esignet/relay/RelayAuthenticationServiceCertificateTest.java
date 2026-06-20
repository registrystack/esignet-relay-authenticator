package io.registry.esignet.relay;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.mosip.esignet.api.dto.KycSigningCertificateData;
import io.mosip.esignet.api.exception.KycSigningCertificateException;
import io.registry.esignet.relay.auth.StaticOtpChallengeVerifier;
import io.registry.esignet.relay.kyc.ClaimMapper;
import io.registry.esignet.relay.kyc.KycSigningKeyService;
import io.registry.esignet.relay.kyc.KycTokenService;
import io.registry.esignet.relay.kyc.TestSigningKeys;
import io.registry.esignet.relay.kyc.UserInfoSigner;
import io.registry.esignet.relay.relay.RelayAttributeReleaseClient;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * M6 tests for {@link RelayAuthenticationService#getAllKycSigningCertificates()}: returns one
 * certificate whose {@code keyId} equals the JWS {@code kid}, whose PEM parses back to the signing
 * certificate, and with populated {@code issuedAt}/{@code expiryAt}; and fails closed with
 * {@code relay_kyc_signing_unavailable} when the signing key cannot be loaded.
 */
class RelayAuthenticationServiceCertificateTest {

  private RelayAuthenticatorProperties props;
  private TestSigningKeys.Bundle bundle;
  private KycSigningKeyService signingKeyService;
  private UserInfoSigner userInfoSigner;
  private RelayAuthenticationService service;

  @BeforeEach
  void setUp() {
    props = TestProperties.valid();
    props.getEsignet().getAuth().getOtp().setStaticEnabled(true);
    props.validate();

    bundle = TestSigningKeys.generate();
    signingKeyService =
        new KycSigningKeyService(
            bundle.keyStore(), TestSigningKeys.ALIAS, TestSigningKeys.PASSWORD, "RS256");
    userInfoSigner = new UserInfoSigner(signingKeyService);

    service =
        new RelayAuthenticationService(
            props,
            new StaticOtpChallengeVerifier(props),
            new RelayAttributeReleaseClient(props),
            new KycTokenService(props),
            new ClaimMapper(props),
            userInfoSigner,
            signingKeyService);
  }

  @Test
  void returnsOneCertificateWithKeyIdMatchingJwsKidAndParseablePem() throws Exception {
    List<KycSigningCertificateData> certs = service.getAllKycSigningCertificates();

    assertEquals(1, certs.size(), "exactly one signing certificate");
    KycSigningCertificateData cert = certs.get(0);

    // keyId MUST equal the JWS header kid produced by the same signing key.
    assertEquals(signingKeyService.getKid(), cert.getKeyId(), "keyId must equal the JWS kid");

    // The kid in a signed JWS header must match too.
    String jws = userInfoSigner.sign(java.util.Map.of("sub", "psut"));
    String headerJson =
        new String(
            java.util.Base64.getUrlDecoder().decode(jws.split("\\.")[0]), StandardCharsets.UTF_8);
    assertTrue(headerJson.contains("\"kid\":\"" + cert.getKeyId() + "\""),
        "JWS header kid must equal the certificate keyId");

    // PEM parses back to the same signing certificate.
    assertNotNull(cert.getCertificateData());
    assertTrue(cert.getCertificateData().contains("BEGIN CERTIFICATE"), "must be PEM");
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate parsed =
        (X509Certificate)
            cf.generateCertificate(
                new ByteArrayInputStream(cert.getCertificateData().getBytes(StandardCharsets.UTF_8)));
    assertEquals(bundle.certificate(), parsed, "PEM must parse back to the signing certificate");

    // Validity window populated.
    assertNotNull(cert.getIssuedAt(), "issuedAt must be populated");
    assertNotNull(cert.getExpiryAt(), "expiryAt must be populated");
    assertTrue(cert.getExpiryAt().isAfter(cert.getIssuedAt()), "expiryAt must be after issuedAt");
  }

  @Test
  void failsClosedWhenSigningKeyUnavailable() {
    // A tolerant signing service pointing at a non-existent keystore: context loaded, but the
    // certificate call must fail closed with the stable code.
    RelayAuthenticatorProperties bad = TestProperties.valid();
    bad.getEsignet().getKyc().getSigning().setKeystorePath("/nonexistent/keystore.p12");
    KycSigningKeyService lazyBad = KycSigningKeyService.lazyFromProperties(bad);

    RelayAuthenticationService badService =
        new RelayAuthenticationService(
            bad,
            new StaticOtpChallengeVerifier(bad),
            new RelayAttributeReleaseClient(bad),
            new KycTokenService(bad),
            new ClaimMapper(bad),
            new UserInfoSigner(lazyBad),
            lazyBad);

    KycSigningCertificateException ex =
        assertThrows(KycSigningCertificateException.class, badService::getAllKycSigningCertificates);
    assertEquals("relay_kyc_signing_unavailable", ex.getErrorCode());
  }
}
