package io.registry.esignet.relay.kyc;

import java.util.Collections;
import java.util.List;

/**
 * Parsed and validated claims from a successfully verified KYC token.
 *
 * <p>All claims have been signature-verified and binding-checked by
 * {@link KycTokenService#verify} before this object is returned. Callers must not log raw
 * field values; sub/sid in particular carry subject identifiers.
 */
public final class KycTokenClaims {

  /** {@code iss} — fixed value {@code esignet-relay-authenticator}. */
  private final String iss;

  /** {@code aud} — fixed value {@code esignet-kyc-exchange}. */
  private final String aud;

  /** {@code sub} — Relay subject value (national ID etc.). */
  private final String sub;

  /** {@code sid} — subject ID type, for example {@code national_id}. */
  private final String sid;

  /** {@code rp} — relying party ID. */
  private final String rp;

  /** {@code client_id} — OIDC client ID. */
  private final String clientId;

  /** {@code txn} — eSignet transaction ID. */
  private final String txn;

  /** {@code amr} — verified authentication methods. */
  private final List<String> amr;

  /** {@code jti} — unique token identifier. */
  private final String jti;

  /** {@code iat} — issued-at epoch seconds. */
  private final long iat;

  /** {@code exp} — expiry epoch seconds. */
  private final long exp;

  /**
   * All-args constructor. Called by {@link KycTokenService} after parsing and verifying the token.
   */
  public KycTokenClaims(
      String iss,
      String aud,
      String sub,
      String sid,
      String rp,
      String clientId,
      String txn,
      List<String> amr,
      String jti,
      long iat,
      long exp) {
    this.iss = iss;
    this.aud = aud;
    this.sub = sub;
    this.sid = sid;
    this.rp = rp;
    this.clientId = clientId;
    this.txn = txn;
    this.amr = amr == null ? Collections.emptyList() : Collections.unmodifiableList(amr);
    this.jti = jti;
    this.iat = iat;
    this.exp = exp;
  }

  public String getIss() {
    return iss;
  }

  public String getAud() {
    return aud;
  }

  /** Subject value — carries the raw subject identifier. Do not log. */
  public String getSub() {
    return sub;
  }

  /** Subject ID type. */
  public String getSid() {
    return sid;
  }

  public String getRp() {
    return rp;
  }

  public String getClientId() {
    return clientId;
  }

  public String getTxn() {
    return txn;
  }

  public List<String> getAmr() {
    return amr;
  }

  public String getJti() {
    return jti;
  }

  public long getIat() {
    return iat;
  }

  public long getExp() {
    return exp;
  }

  /** Redacted view. Never prints sub (subject value) or txn (transaction ID). */
  @Override
  public String toString() {
    return "KycTokenClaims{iss="
        + iss
        + ", aud="
        + aud
        + ", sub=[REDACTED]"
        + ", sid="
        + sid
        + ", rp="
        + rp
        + ", clientId="
        + clientId
        + ", txn=[REDACTED]"
        + ", amr="
        + amr
        + ", jti="
        + jti
        + ", iat="
        + iat
        + ", exp="
        + exp
        + "}";
  }
}
