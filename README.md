# eSignet Relay Authenticator

An [eSignet](https://github.com/mosip/esignet) `Authenticator` SPI plugin that verifies an
authentication challenge and obtains consent-limited identity properties from Registry Relay V2.

Version 0.2.0 uses one governed Relay consultation lookup:

```text
POST /v2/resources/{resource}/lookups/{lookup}?fields=...&accessProfile=...
```

The request body is exactly `{"selectors":{"uin":"..."}}`. The plugin reads identity values only
from `data.domainData`. It does not use Relay V1 attribute-release routes, static bearer tokens,
client secrets, caller purpose headers, or broad record-list APIs.

## Security and privacy behavior

- The configured `ChallengeVerifier` succeeds before any Mint or Relay call.
- `doKycAuth` requests only the provisioned account-check property, by default `individual_id`.
- `doKycExchange` sends only the intersection of eSignet-consented claims, the configured claim map,
  and `registry.relay.default-claims`.
- The selector is present only in the JSON body. It is never placed in a path, query, exception, or
  log.
- Relay access tokens come from Registry Mint OAuth client credentials using `private_key_jwt`.
  Assertions have exact token-endpoint audience, `iss == sub == client_id`, a configured `kid`, a
  fresh `jti`, and bounded `iat`/`exp`. No client secret is supported.
- The token cache is process-local and single-flight. Its lifetime is the smaller of Mint's
  `expires_in` and `registry.mint.token-cache-max-seconds`. Rejected, expired, and replaced token
  buffers are cleared.
- Relay unresolved, concealed, and denied outcomes produce one generic non-retryable subject denial.
  Mint, Relay authentication, audit/source availability, timeout, malformed response, and transport
  failures produce one generic retryable unavailable outcome. HTTP status alone is never used to
  infer membership.
- The plugin preserves partner-specific subjects (PSUT), its short-lived internal KYC token, and the
  self-contained RS256 KYC/UserInfo JWS.

## Requirements and build

| Requirement | Version |
|---|---|
| eSignet integration API | 1.8.0 |
| Java | 21 |
| Maven | 3.9+ |

```bash
mvn -B -ntp verify
```

The artifact is `target/esignet-relay-authenticator-0.2.0.jar`. A `v0.2.0` tag publishes the JAR and
`esignet-relay-authenticator-0.2.0.jar.sha256` as GitHub Release assets.

Tests use local JDK HTTP stubs for both Registry Mint and Relay. No live Registry Stack or eSignet
deployment is required.

The plugin implements `doKycAuth`, both KYC exchange variants, `sendOtp`, supported-channel lookup,
and KYC signing-certificate publication. eSignet supplies the integration API, Spring, and Jackson
at runtime through `provided` Maven dependencies.

## Minimal configuration

```properties
mosip.esignet.integration.scan-base-package=io.registry.esignet.relay
mosip.esignet.integration.authenticator=RelayAuthenticationService

registry.relay.base-url=https://registry-relay.example.org
registry.relay.resource=civil-person
registry.relay.lookup=by-uin
registry.relay.access-profile=esignet
registry.relay.default-claims=individual_id,name,given_name,family_name,birthdate

registry.mint.token-endpoint=https://registry-mint.example.org/token
registry.mint.client-id=esignet-relay-authenticator
registry.mint.private-jwk=${REGISTRY_MINT_CLIENT_PRIVATE_JWK}

registry.esignet.subject-id-type=uin
registry.esignet.account-check-claims=individual_id
registry.esignet.auth.supported-factors=OTP
registry.esignet.auth.otp.static-enabled=false

registry.esignet.kyc-token.hmac-secret=${REGISTRY_ESIGNET_KYC_TOKEN_SECRET}
registry.esignet.psut.hmac-secret=${REGISTRY_ESIGNET_PSUT_SECRET}
registry.esignet.kyc.signing.keystore-path=${REGISTRY_ESIGNET_KYC_KEYSTORE_PATH}
registry.esignet.kyc.signing.keystore-password=${REGISTRY_ESIGNET_KYC_KEYSTORE_PASSWORD}
registry.esignet.kyc.signing.key-alias=${REGISTRY_ESIGNET_KYC_KEY_ALIAS}
registry.esignet.kyc.signing.key-password=${REGISTRY_ESIGNET_KYC_KEY_PASSWORD}
```

`registry.relay.access-profile` is optional only when the Relay operation's default access profile is
the intended contract. When configured, it is sent as `accessProfile`. Authority and purpose remain
verified token claims minted from Registry Mint's server-side client registration, never caller
headers or query hints.

The supported Mint key source is a secret-provided RSA private JWK with `kty=RSA`, `alg=RS256`, a
non-empty `kid`, modulus at least 2048 bits, and private CRT members `n`, `e`, `d`, `p`, `q`, `dp`,
`dq`, and `qi`. The complete JWK is redacted by configuration rendering and must not be committed.

## Static OTP warning

The bundled static OTP verifier is for local demonstrations only. It is disabled by default and is
not a production authentication mechanism. Production deployments must provide a real
`ChallengeVerifier` bean.

## KYC response

The plugin issues an internal HS256 KYC token bound to relying party, client, transaction, subject,
and subject-id type. During exchange it derives a deterministic PSUT and signs the resulting UserInfo
as a compact RS256 JWS. `getAllKycSigningCertificates` returns the matching X.509 certificate.

JWE is not supported by the eSignet 1.8.0 integration surface used here. A JWE request fails before
Relay disclosure. Verified exchange does not fabricate assurance evidence that Relay did not return.

## Known limitations

- The internal KYC token is short-lived and bound to relying party, client, transaction, subject, and
  subject-id type, but this version does not maintain a persistent single-use `jti` store. Protect it
  as a bearer credential and keep its TTL short.
- JWE remains fail-closed until the eSignet integration surface provides the relying-party encryption
  key to the authenticator.
- Verified exchange cannot emit assurance metadata absent from Relay V2 `domainData` and does not
  synthesize it.
- This repository provides self-contained contract and service tests. A live eSignet, Mint, and Relay
  smoke remains a deployment responsibility.

## Failure codes

| Code | Meaning |
|---|---|
| `relay_auth_invalid_request` | Invalid local eSignet request |
| `relay_auth_challenge_failed` | Challenge verification failed |
| `relay_auth_subject_denied` | Generic non-retryable Relay denial, including unresolved or concealed |
| `relay_auth_relay_unavailable` | Generic retryable Mint/Relay authentication, source, audit, timeout, response, or transport failure |
| `relay_auth_token_invalid` / `relay_auth_token_expired` | Internal KYC token failure |
| `relay_kyc_jwe_unsupported` | JWE requested but unavailable, failed before lookup |
| `relay_kyc_signing_failed` / `relay_kyc_signing_unavailable` | KYC signing failure |

See [configuration](docs/esignet-configuration.md), the [Relay V2 contract](docs/relay-attribute-release-contract.md),
the [plugin specification](docs/esignet-relay-authenticator-plugin-spec.md), and the
[deployment guide](docs/solmara-lab-deployment.md).
