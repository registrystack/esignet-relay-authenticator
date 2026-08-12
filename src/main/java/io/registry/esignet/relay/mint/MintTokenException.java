package io.registry.esignet.relay.mint;

/** Value-free failure to obtain a Relay access token from Registry Mint. */
public final class MintTokenException extends Exception {
  public MintTokenException() {
    super("Registry Mint access token is unavailable");
  }
}
