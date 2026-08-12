# Solmara Lab deployment

## Prerequisites

- eSignet 1.8.0 running on Java 21
- Registry Relay V2 with a packaged lookup that accepts exactly the `uin` selector
- A compiled Relay access profile whose selectable properties cover the plugin's configured list
- Registry Mint with the plugin registered as a `private_key_jwt` OAuth client
- A production `ChallengeVerifier`
- Independent KYC-token, PSUT, Mint client, and KYC signing keys

The Relay access profile must authorize the Mint-issued token through verified claims. Do not add a
caller purpose header or query parameter. If explicit selection is required, configure the exact
compiled `accessProfile` identifier.

## Artifact

Release `v0.2.0` publishes:

```text
esignet-relay-authenticator-0.2.0.jar
esignet-relay-authenticator-0.2.0.jar.sha256
```

Verify before copying the JAR into the eSignet plugin classpath:

```bash
sha256sum --check esignet-relay-authenticator-0.2.0.jar.sha256
```

On macOS, compare `shasum -a 256 esignet-relay-authenticator-0.2.0.jar` with the checksum file.

For a source build, run `mvn -B -ntp verify` and use
`target/esignet-relay-authenticator-0.2.0.jar`. Mount the JAR in the plugin directory configured by
the `esignet-with-plugins` loader rather than adding it to the base image manually.

## Registry Mint registration

Generate the RSA key in an approved secret system. Give eSignet only the private JWK. Register only
the corresponding public JWK with Mint, including the same `kid` and `alg=RS256`. The Mint client
registration owns Relay scopes and any required authority or purpose claims. No scope is submitted in
the runtime token request.

Set the assertion audience to the exact externally reachable Mint token endpoint. Differences in
scheme, host, port, path, or trailing slash cause Mint to reject the client assertion.

## eSignet properties

```properties
mosip.esignet.integration.scan-base-package=io.registry.esignet.relay
mosip.esignet.integration.authenticator=RelayAuthenticationService

registry.relay.base-url=https://registry-relay.internal
registry.relay.resource=civil-person
registry.relay.lookup=by-uin
registry.relay.access-profile=esignet
registry.relay.default-claims=individual_id,name,given_name,family_name,birthdate

registry.mint.token-endpoint=https://registry-mint.internal/token
registry.mint.client-id=esignet-relay-authenticator
registry.mint.private-jwk=${REGISTRY_MINT_CLIENT_PRIVATE_JWK}

registry.esignet.subject-id-type=uin
registry.esignet.account-check-claims=individual_id
registry.esignet.auth.otp.static-enabled=false

registry.esignet.kyc-token.hmac-secret=${REGISTRY_ESIGNET_KYC_TOKEN_SECRET}
registry.esignet.psut.hmac-secret=${REGISTRY_ESIGNET_PSUT_SECRET}
registry.esignet.kyc.signing.keystore-path=${REGISTRY_ESIGNET_KYC_KEYSTORE_PATH}
registry.esignet.kyc.signing.keystore-password=${REGISTRY_ESIGNET_KYC_KEYSTORE_PASSWORD}
registry.esignet.kyc.signing.key-alias=${REGISTRY_ESIGNET_KYC_KEY_ALIAS}
registry.esignet.kyc.signing.key-password=${REGISTRY_ESIGNET_KYC_KEY_PASSWORD}
```

Use HTTPS for Mint and Relay. The startup warning for plaintext non-loopback URLs is diagnostic, not
a TLS substitute.

## Smoke verification

1. Start eSignet and confirm the authenticator bean loads without printing secret configuration.
2. Submit an invalid challenge and verify neither Mint nor Relay receives a request.
3. Submit a valid challenge for a test subject and verify Mint receives one client-credentials
   request, then Relay receives one `POST /v2/resources/.../lookups/...` request.
4. Confirm the Relay body is exactly `{"selectors":{"uin":"..."}}` and the account-check `fields`
   query contains no demographic properties.
5. Perform KYC exchange with a small accepted-claims set and confirm Relay receives only that
   provisioned intersection.
6. Confirm unresolved, concealed, and denied records yield the same eSignet error code.
7. Interrupt Mint or Relay and confirm the retryable unavailable error exposes no response body,
   selector, token, assertion, or source value.
8. Verify the returned KYC JWS against the certificate published by eSignet.

Keep static OTP disabled outside an isolated local demonstration.
