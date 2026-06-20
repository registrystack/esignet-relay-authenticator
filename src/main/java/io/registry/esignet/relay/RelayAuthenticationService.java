package io.registry.esignet.relay;

import io.mosip.esignet.api.dto.KycAuthDto;
import io.mosip.esignet.api.dto.KycAuthResult;
import io.mosip.esignet.api.dto.KycExchangeDto;
import io.mosip.esignet.api.dto.KycExchangeResult;
import io.mosip.esignet.api.dto.KycSigningCertificateData;
import io.mosip.esignet.api.dto.SendOtpDto;
import io.mosip.esignet.api.dto.SendOtpResult;
import io.mosip.esignet.api.dto.VerifiedKycExchangeDto;
import io.mosip.esignet.api.exception.KycAuthException;
import io.mosip.esignet.api.exception.KycExchangeException;
import io.mosip.esignet.api.exception.KycSigningCertificateException;
import io.mosip.esignet.api.exception.SendOtpException;
import io.mosip.esignet.api.spi.Authenticator;
import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * eSignet {@link Authenticator} backed by Registry Relay's governed attribute release endpoint.
 *
 * <p>Loaded by eSignet only when {@code mosip.esignet.integration.authenticator} equals
 * {@link #BEAN_NAME}. This is the M0 skeleton: methods are intentionally unimplemented and are
 * filled in by later milestones (see {@code docs/GOAL.md}).
 */
@Component
@ConditionalOnProperty(
    value = "mosip.esignet.integration.authenticator",
    havingValue = RelayAuthenticationService.BEAN_NAME)
public class RelayAuthenticationService implements Authenticator {

  /** Conditional bean-loading value eSignet matches against. */
  public static final String BEAN_NAME = "RelayAuthenticationService";

  private static final String NOT_IMPLEMENTED = "not_implemented";

  @Override
  public KycAuthResult doKycAuth(String relyingPartyId, String clientId, KycAuthDto kycAuthDto)
      throws KycAuthException {
    throw new KycAuthException(NOT_IMPLEMENTED);
  }

  @Override
  public KycExchangeResult doKycExchange(
      String relyingPartyId, String clientId, KycExchangeDto kycExchangeDto)
      throws KycExchangeException {
    throw new KycExchangeException(NOT_IMPLEMENTED);
  }

  @Override
  public KycExchangeResult doVerifiedKycExchange(
      String relyingPartyId, String clientId, VerifiedKycExchangeDto kycExchangeDto)
      throws KycExchangeException {
    throw new KycExchangeException(NOT_IMPLEMENTED);
  }

  @Override
  public SendOtpResult sendOtp(String relyingPartyId, String clientId, SendOtpDto sendOtpDto)
      throws SendOtpException {
    throw new SendOtpException(NOT_IMPLEMENTED);
  }

  @Override
  public boolean isSupportedOtpChannel(String channel) {
    return false;
  }

  @Override
  public List<KycSigningCertificateData> getAllKycSigningCertificates()
      throws KycSigningCertificateException {
    throw new KycSigningCertificateException(NOT_IMPLEMENTED);
  }
}
