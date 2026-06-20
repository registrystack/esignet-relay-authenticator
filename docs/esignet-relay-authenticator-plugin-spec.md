# eSignet Relay Authenticator plugin implementation brief

Page type: implementation handoff spec
Product: eSignet, Registry Relay
Layer: authentication, identity attribute release, OIDC UserInfo
Audience: Codex Cloud implementer working in `jeremi/esignet-relay-authenticator`
Status: draft for implementation

> Revision note (2026-06-20): error handling, the Relay contract section, and
> the test matrix were corrected to match the Relay-side brief's **collapsed
> public denial** design. The plugin cannot distinguish subject-not-found,
> ambiguous, release-denied, and required-claim-missing — Relay returns one
> `release.subject_denied` for all four. See `docs/relay-attribute-release-contract.md`.

## Assignment

You are working in this GitHub repository only:

```text
https://github.com/jeremi/esignet-relay-authenticator
```

Build an eSignet Authenticator plugin that uses Registry Relay as the account
and identity attribute source.

Do not edit `registry-relay`, `registry-lab`, `registry-internal`, MOSIP
eSignet, or MOSIP plugin repositories. This repository should contain the plugin
code, tests, build files, packaging instructions, and a local contract fixture
for the Relay endpoint it expects.

Before making changes:

- Read the repository README and any `AGENTS.md` if present.
- Inspect the current eSignet Authenticator plugin interface for the target
  eSignet version.
- Inspect MOSIP's mock Authenticator plugin as the primary structural template
  for local KYC signing and certificate exposure. The MOSIP IDA plugin is useful
  for interface shape, but it offloads KYC packaging to IDA and should not be
  copied as the standalone crypto design.
- Read Registry Relay's current API docs only for conventions: `Authorization:
  Bearer`, `Data-Purpose`, scope naming, RFC 9457 problem details, and audit
  posture. The attribute release endpoint itself is a new contract being
  implemented in `registry-relay`, not an endpoint that exists in today's
  released Relay API.
- Read `docs/relay-attribute-release-contract.md` in this repository. It mirrors
  the Relay-side brief and is the source of truth for the Relay client and its
  test stub.
- Keep the repository self-contained. Do not vendor large upstream repositories
  or generated source.

Before finishing:

- Add focused unit tests for Relay client behavior, authentication decisions,
  token handling, claim mapping, error mapping, and config validation.
- Add at least one contract test using a stub Relay attribute release endpoint.
- Add README instructions for building the JAR and configuring eSignet to load
  it.
- Run `mvn test` and a package/build command before declaring the work complete.
  If any verification cannot run, explain exactly why.

## Goal

Create a Java eSignet Authenticator plugin that lets eSignet authenticate a
person against Registry Relay and fetch consented OIDC/UserInfo claims from a
Relay governed attribute release profile.

Target flow:

```text
User enters individual ID in eSignet
  -> eSignet calls Authenticator.sendOtp, if OTP is enabled
  -> user submits OTP, PIN, or configured challenge
  -> eSignet calls Authenticator.doKycAuth
  -> plugin verifies the challenge and checks Relay for the subject
  -> plugin returns a KYC token and partner-specific subject
  -> eSignet handles consent and token issuance
  -> eSignet calls Authenticator.doKycExchange
  -> plugin calls Relay attribute release with consented claims
  -> plugin returns signed/encrypted KYC/UserInfo data in eSignet's expected form
```

Registry Relay is the source of identity attributes. eSignet remains the OIDC
provider. The plugin is the bridge between them.

## Non-goals

- Do not implement the Relay attribute release endpoint here.
- Do not expose a generic Relay row-read client as the eSignet integration.
- Do not sync Relay data into eSignet or MOSIP mock identity storage.
- Do not build lab Compose wiring in this repository.
- Do not invent a custom OIDC provider flow outside eSignet's Authenticator
  interface.
- Do not log raw identifiers, OTPs, KYC tokens, Relay tokens, or released
  attributes.

## Upstream anchors

Use current upstream sources as implementation references. The known target at
the time this spec was written is eSignet `1.8.0`, Java `21`, Maven, and the
`io.mosip.esignet:esignet-integration-api` Authenticator interface.

Known Authenticator methods to implement:

```java
KycAuthResult doKycAuth(String relyingPartyId, String clientId, KycAuthDto kycAuthDto)
        throws KycAuthException;

KycAuthResult doKycAuth(String relyingPartyId, String clientId,
        boolean claimsMetadataRequired, KycAuthDto kycAuthDto)
        throws KycAuthException;

KycExchangeResult doKycExchange(String relyingPartyId, String clientId,
        KycExchangeDto kycExchangeDto)
        throws KycExchangeException;

KycExchangeResult doVerifiedKycExchange(String relyingPartyId, String clientId,
        VerifiedKycExchangeDto kycExchangeDto)
        throws KycExchangeException;

SendOtpResult sendOtp(String relyingPartyId, String clientId, SendOtpDto sendOtpDto)
        throws SendOtpException;

boolean isSupportedOtpChannel(String channel);

List<KycSigningCertificateData> getAllKycSigningCertificates()
        throws KycSigningCertificateException;
```

In eSignet `1.8.0`, the overload
`doKycAuth(String, String, boolean, KycAuthDto)` and
`doVerifiedKycExchange(String, String, VerifiedKycExchangeDto)` are default
interface methods. Override them anyway so claims metadata and verified-KYC
behavior are explicit and tested.

Known eSignet plugin loading properties:

```properties
mosip.esignet.integration.scan-base-package=<plugin package>
mosip.esignet.integration.authenticator=<Spring bean condition value>
```

Treat these as anchors, not frozen truth. If upstream eSignet has changed,
adapt to the target version and document the version you implemented against.

## Repository shape

Create a Maven project that builds a plugin JAR.

Suggested layout:

```text
.
+-- README.md
+-- pom.xml
+-- src
|   +-- main
|   |   +-- java
|   |   |   +-- io/registry/esignet/relay
|   |   |       +-- RelayAuthenticationService.java
|   |   |       +-- RelayAuthenticatorProperties.java
|   |   |       +-- relay/
|   |   |       +-- auth/
|   |   |       +-- kyc/
|   |   |       +-- support/
|   |   +-- resources
|   |       +-- application.properties
|   +-- test
|       +-- java
|       +-- resources
+-- docs
    +-- relay-attribute-release-contract.md
    +-- esignet-configuration.md
```

Suggested Maven coordinates:

```xml
<groupId>io.registry.esignet</groupId>
<artifactId>esignet-relay-authenticator</artifactId>
<version>0.1.0-SNAPSHOT</version>
```

Expected dependency posture:

- Java 21.
- Maven.
- `io.mosip.esignet:esignet-integration-api` as `provided`.
- Test dependencies may include JUnit 5, Mockito, and a lightweight HTTP stub.
- Use Java 21's built-in `java.net.http.HttpClient` for Relay calls unless a
  required eSignet runtime dependency already provides a better local pattern.
- Keep runtime dependencies minimal so the JAR can be mounted into eSignet
  without classpath surprises.

## Spring bean loading

Implement the Authenticator as a Spring component gated by the standard eSignet
conditional property.

Suggested class:

```java
package io.registry.esignet.relay;

@Component
@ConditionalOnProperty(
    value = "mosip.esignet.integration.authenticator",
    havingValue = "RelayAuthenticationService"
)
public class RelayAuthenticationService implements Authenticator {
    ...
}
```

Suggested eSignet properties:

```properties
mosip.esignet.integration.scan-base-package=io.registry.esignet.relay
mosip.esignet.integration.authenticator=RelayAuthenticationService
```

## Relay contract expected by the plugin

The plugin depends on a new Registry Relay governed attribute release endpoint.
Do not call Relay's generic row-read API as a substitute. The Relay-side feature
may be implemented separately, so this repository carries a shared contract
document and test stub for the endpoint it expects.

`docs/relay-attribute-release-contract.md` is the local source of truth for the
stub tests. Keep it aligned with the Relay-side handoff brief
(`registry-internal/docs/registry-relay/esignet-identity-attribute-release-spec.md`)
and record the Relay spec revision you aligned to. The contract is:

- `POST /v1/attribute-releases/{profile_id}/versions/{version}/resolve`;
- `Authorization: Bearer <api-key-or-oidc-access-token>`;
- `Data-Purpose` header;
- `Content-Type: application/json`;
- `Accept: application/json`;
- a release scope such as `civil_registry:identity_release`;
- RFC 9457 `application/problem+json` errors with a machine-readable `code`.

Relay uses `Authorization: Bearer` on the wire for both raw API keys and OIDC
access tokens. Do not implement an `X-API-Key` transport path.

Expected request:

```http
POST /v1/attribute-releases/{profile_id}/versions/{version}/resolve
Authorization: Bearer <api-key-or-oidc-access-token>
Data-Purpose: https://demo.example.gov/purpose/esignet-identity-verification
Content-Type: application/json
Accept: application/json
```


```json
{
  "subject": {
    "id_type": "national_id",
    "value": "NID-2001"
  },
  "claims": ["individual_id", "name", "given_name", "family_name", "birthdate"]
}
```

Expected success response:

```json
{
  "profile_id": "esignet-civil-userinfo",
  "profile_version": "v1",
  "purpose": "https://demo.example.gov/purpose/esignet-identity-verification",
  "claims": {
    "individual_id": "NID-2001",
    "given_name": "Maria",
    "family_name": "Santos",
    "name": "Maria Santos",
    "birthdate": "1984-01-15"
  },
  "source": {
    "dataset": "civil_registry",
    "entity": "civil_person_detail",
    "subject_id_type": "national_id",
    "cardinality": "one",
    "checked_at": "2026-06-20T00:00:00Z"
  }
}
```

### Failure model (read this carefully)

Relay returns RFC 9457 problem details. **Branch on the `code` field, never on
HTTP status alone** — several distinct meanings share a status. The `detail`
string is scrubbed and must not be parsed.

Relay deliberately **collapses** subject-sensitive outcomes into a single public
denial for anti-enumeration. The plugin therefore receives:

Distinguishable outcomes (each a distinct `code`; most indicate
plugin/deployment misconfiguration in normal operation):

| Relay `code` | HTTP | Meaning |
| --- | --- | --- |
| `release.profile_not_found` | 404 | unknown/invisible profile or version |
| `auth.scope_denied` | 403 | caller lacks the release scope |
| `auth.purpose_required` | 400 | missing `Data-Purpose` |
| `auth.purpose_denied` | 403 | purpose not permitted by governed policy |
| `release.subject_invalid` | 400 | bad id type or malformed subject value |
| `release.source_unavailable` | 503 | source read failed |

Plus transport timeout / no response → relay-unavailable.

Collapsed outcome (one public `code`; finer reasons exist only in Relay audit
and are **never** visible to the plugin):

| Relay public `code` | Collapses (audit-only) |
| --- | --- |
| `release.subject_denied` | subject not found; ambiguous (>1); release condition denied (e.g. deceased/inactive); required claim unavailable |

The plugin must map these to eSignet Authenticator exceptions without leaking
raw Relay response bodies to logs, and must not attempt to distinguish or
disclose the collapsed sub-reasons.

## Configuration

Add typed configuration with validation. Fail fast during startup when required
security-sensitive settings are missing.

Suggested properties:

```properties
# eSignet plugin loading
mosip.esignet.integration.scan-base-package=io.registry.esignet.relay
mosip.esignet.integration.authenticator=RelayAuthenticationService

# Relay endpoint
registry.relay.base-url=http://registry-relay:8080
registry.relay.attribute-release.profile-id=esignet-civil-userinfo
registry.relay.attribute-release.profile-version=v1
registry.relay.attribute-release.path-template=/v1/attribute-releases/{profile_id}/versions/{version}/resolve
registry.relay.attribute-release.purpose=https://demo.example.gov/purpose/esignet-identity-verification
registry.relay.attribute-release.accept=application/json
registry.relay.subject.id-type=national_id
registry.relay.default-claims=individual_id,name,given_name,family_name,birthdate
registry.relay.connect-timeout-ms=2000
registry.relay.read-timeout-ms=5000

# Relay authorization. Always sent as Authorization: Bearer on the wire.
# credential-kind is an operator label for validation/docs, not a header scheme.
registry.relay.auth.credential-kind=api_key
registry.relay.auth.bearer-token=${REGISTRY_RELAY_TOKEN}

# Authentication challenge verification
registry.esignet.auth.supported-factors=OTP
registry.esignet.auth.otp.channels=email,phone
registry.esignet.auth.otp.mode=static
registry.esignet.auth.otp.static-value=${REGISTRY_ESIGNET_STATIC_OTP:111111}
registry.esignet.auth.otp.static-enabled=false

# Internal KYC token and partner-specific subject derivation
registry.esignet.kyc-token.hmac-secret=${REGISTRY_ESIGNET_KYC_TOKEN_SECRET}
registry.esignet.kyc-token.ttl-seconds=300
registry.esignet.psut.hmac-secret=${REGISTRY_ESIGNET_PSUT_SECRET}

# Claim mapping (eSignet/OIDC UserInfo claim name -> Relay source token).
# $psut marks a protocol-derived claim (the PSUT) supplied locally, never requested from Relay.
# Dotted keys bind via claim-map[<dotted.name>]. Defaults to the map below when unset.
registry.esignet.claim-map.sub=$psut
registry.esignet.claim-map.individual_id=individual_id
registry.esignet.claim-map.name=name
registry.esignet.claim-map.given_name=given_name
registry.esignet.claim-map.family_name=family_name
registry.esignet.claim-map.birthdate=birthdate
registry.esignet.claim-map.gender=gender
registry.esignet.claim-map[address.region]=address.region

# KYC/UserInfo serialization and signing
registry.esignet.kyc.response-mode=self-contained-jws
# algorithm (default RS256) and keystore-type (default PKCS12) are optional.
registry.esignet.kyc.signing.algorithm=RS256
registry.esignet.kyc.signing.keystore-type=PKCS12
registry.esignet.kyc.signing.keystore-path=${REGISTRY_ESIGNET_KYC_KEYSTORE_PATH}
registry.esignet.kyc.signing.keystore-password=${REGISTRY_ESIGNET_KYC_KEYSTORE_PASSWORD}
registry.esignet.kyc.signing.key-alias=${REGISTRY_ESIGNET_KYC_KEY_ALIAS}
registry.esignet.kyc.signing.key-password=${REGISTRY_ESIGNET_KYC_KEY_PASSWORD}
```

> **M6 implemented (2026-06-20):** the claim mapper, the RS256 JWS signer + signing
> keystore loader, and `getAllKycSigningCertificates`.
>
> - **Algorithm:** `RS256` (configurable via `registry.esignet.kyc.signing.algorithm`,
>   published in the JWS header `alg`).
> - **`kid` scheme:** `base64url(SHA-256(RFC 7638 JWK thumbprint))` of the RSA public
>   key — the canonical JSON is `{"e":...,"kty":"RSA","n":...}` with `e`/`n` as
>   minimal-length base64url-encoded big-endian integers. The same key always yields the
>   same `kid`; the JWS header `kid` equals the `keyId` returned by
>   `getAllKycSigningCertificates`.
> - **JWE fail-closed:** a JWE `userInfoResponseType` throws a checked
>   `UserInfoPackagingException` with stable code `relay_kyc_jwe_unsupported` and emits no
>   token. The RP encryption key is not available to the plugin (not in `KycExchangeDto`
>   nor any eSignet `1.8.0` integration runtime API), so per spec we must not return
>   unencrypted data for a JWE request. Supplying the RP encryption JWK/cert via the
>   exchange DTO or an integration API would unblock real JWE.
> - **New properties:** `registry.esignet.claim-map.*`, `registry.relay.default-claims`
>   (the profile-declared claim set, now bound), `registry.esignet.kyc.signing.algorithm`,
>   `registry.esignet.kyc.signing.keystore-type`.
> - **Signing material in tests:** tests generate an RSA-2048 keypair + self-signed X.509
>   cert (BouncyCastle, test scope only) into an in-memory keystore fed to the same
>   production `KycSigningKeyService` keystore constructor. Main code is pure JDK crypto;
>   no committed keys or keystores.

Important behavior:

- `registry.esignet.auth.otp.static-enabled` must default to `false`.
- Static OTP mode is for local development and lab demos only.
- Production deployments must provide a real `ChallengeVerifier`, such as an
  OTP manager, Relay-backed verification endpoint, or jurisdiction-specific
  authenticator.
- HMAC secrets must be loaded from environment or secret manager, not committed.
- KYC signing keys must be loaded from deployment secrets, not committed.
- The plugin must not print resolved configuration values for secrets.

## Authentication design

Relay can be the account source, but Relay's attribute release endpoint is not
itself an authentication factor. Keep these responsibilities separate.

Implement a small challenge-verifier abstraction:

```text
ChallengeVerifier
  - supports(authFactorType, format, channel)
  - sendOtp(transactionId, individualId, channels, relyingPartyId, clientId)
  - verify(transactionId, individualId, challengeList, relyingPartyId, clientId)
```

Initial required implementation:

- `StaticOtpChallengeVerifier`, disabled by default, for lab demos and tests.
- It supports `OTP` with `alpha-numeric` format.
- It returns masked email/mobile values only when configured to do so.
- It must never log OTP values.
- `sendOtp` must be non-enumerating. For an unknown, ambiguous, release-denied,
  or Relay-unavailable subject, return the same public shape and timing posture
  as a successful OTP request where practical. Preserve distinct internal logs
  only in redacted form.

Optional implementation:

- `ExternalOtpChallengeVerifier` using an HTTP service, only if it can be done
  without broadening the task too much.

In `doKycAuth`:

1. Validate `relyingPartyId`, `clientId`, transaction ID, individual ID, and
   challenge list.
2. Verify the submitted challenge with the configured verifier.
3. Call Relay attribute release with only the minimal account-check claims,
   usually `["individual_id"]`.
4. Require exactly one subject. A `release.subject_denied` response is a single
   collapsed failure — fail closed without inferring the underlying reason.
5. Derive a partner-specific user token.
6. Issue a short-lived internal KYC token.
7. Return `KycAuthResult(kycToken, partnerSpecificUserToken, claimsMetadata)`.

If `claimsMetadataRequired` is true, return conservative metadata only for
claims the plugin can request from Relay. Do not include raw values in metadata.

## KYC token design

The KYC token returned by `doKycAuth` is internal to eSignet/plugin exchange.
It must be tamper-evident and short-lived.

Suggested format:

- Compact JWS or equivalent HMAC-signed token.
- Algorithm: HS256 (HMAC-SHA256) is acceptable for the first implementation if
  the secret is validated and kept out of code.
- Claims:
  - `iss`: `esignet-relay-authenticator`;
  - `aud`: `esignet-kyc-exchange`;
  - `sub`: Relay subject value or its configured canonical account ID;
  - `sid`: subject ID type, such as `national_id`;
  - `rp`: relying party ID;
  - `client_id`: OIDC client ID;
  - `txn`: eSignet transaction ID;
  - `amr`: verified authentication methods;
  - `iat`, `exp`, `jti`.

On exchange, verify:

- signature;
- expiry;
- relying party ID;
- client ID;
- transaction ID;
- individual ID, when eSignet supplies it.

Do not put released demographic claims in the KYC token. Fetch consented claims
from Relay during exchange.

V1 does not require a persistent single-use `jti` store. That means a valid KYC
token can be replayed within its short TTL if an attacker obtains it. Keep the
TTL short, bind the token to relying party, client, transaction, and individual
ID, redact it from logs, and document single-use token storage as production
hardening.

## Partner-specific subject

Return an eSignet partner-specific user token that does not expose the raw
national ID to relying parties.

Suggested v1 derivation:

```text
base64url(HMAC-SHA256(psut_secret, relyingPartyId + "|" + clientId + "|" + subjectIdType + "|" + subjectValue))
```

Keep this deterministic for the same RP/client/subject so relying parties get a
stable subject. Use a different secret from the KYC token secret.

Future work may add Relay-issued opaque or domain-specific subjects. Do not
block this first plugin on that.

## Claim mapping

Map Relay released claims into eSignet/OIDC UserInfo claims. Keep this mapping
configuration-driven so different Relay profiles can be used later.

Suggested default mapping:

```properties
registry.esignet.claim-map.sub=$psut
registry.esignet.claim-map.individual_id=individual_id
registry.esignet.claim-map.name=name
registry.esignet.claim-map.given_name=given_name
registry.esignet.claim-map.family_name=family_name
registry.esignet.claim-map.birthdate=birthdate
registry.esignet.claim-map.gender=gender
registry.esignet.claim-map[address.region]=address.region
```

Rules:

- `sub` must be the partner-specific subject unless eSignet requires a different
  field for its internal KYC payload.
- Request only accepted/consented claims from Relay during KYC exchange.
- **Filter the requested claim list to the profile before calling Relay.** Send
  only `intersection(claims eSignet accepted, claims the active profile/config
  declares)`. Relay V1 denies the *entire* request if any requested claim is
  outside the profile, so optional-claim omission is the plugin's job, not
  Relay's. Never forward an eSignet-accepted claim that the profile does not
  declare.
- Always include claims required by eSignet for protocol correctness, such as
  `sub`, from plugin-derived values rather than broad Relay reads. Do not request
  protocol-derived claims (`sub`, `$psut`) from Relay.
- Treat Relay's released values as authoritative. The Relay profile may compute
  claims server-side (for example `name` from given + family via CEL); do not
  re-synthesize or override them in the plugin.
- If eSignet asks for a claim not allowed by config, omit it for optional claims
  and fail for required claims, per eSignet's expected semantics.
- Preserve scalar JSON types when Relay returns them.
- Do not fabricate missing civil attributes.

## KYC exchange and UserInfo packaging

`doKycExchange` must return a `KycExchangeResult` whose `encryptedKyc` field is
valid for the target eSignet version.

Implementation requirement:

- Inspect eSignet `1.8.0` and its reference plugins to confirm the expected
  signed/encrypted KYC payload format.
- Use the MOSIP eSignet mock plugin as the primary crypto template because it
  performs local KYC signing and certificate exposure. Do not copy the IDA
  plugin's crypto shape as the main design because IDA offloads packaging to an
  external identity service.
- Implement a self-contained JWS signer for v1 using a configured deployment
  keystore. Do not return a plain JSON string.
- Set a stable JWS `kid` in the signed header and ensure the JWK/certificate
  exposed by `getAllKycSigningCertificates` carries the **same** `kid` and
  signing algorithm, so eSignet can publish it and relying parties can verify.
  Document the chosen algorithm (for example RS256).
- If `KycExchangeDto.getUserInfoResponseType()` requests JWE, additionally
  encrypt the signed UserInfo/KYC JWT to the relying party's encryption public
  key using the eSignet-supported mechanism for the target version. The
  implementation must document how it obtains that RP encryption key. If the key
  is not available through eSignet runtime APIs or DTO context, fail closed with
  a stable exchange error rather than returning unencrypted data for a JWE
  request.
- `getAllKycSigningCertificates` and the returned KYC data must agree on the
  signing key.
- Add tests around the serializer/signer using deterministic test keys.
- Document which format was implemented and which runtime properties it needs.

Suggested exchange flow:

1. Verify the KYC token.
2. Determine accepted claims from `KycExchangeDto.getAcceptedClaims()`.
3. Reduce to `intersection(accepted, profile/config-declared)` and add any
   protocol-required claims, such as `sub`, from plugin-derived values.
4. Call Relay attribute release with that consented, profile-filtered claim list.
5. Map Relay claims into the eSignet UserInfo/KYC payload.
6. Sign as JWS, then encrypt as JWE when requested by eSignet/RP.
7. Return `new KycExchangeResult(serializedKyc)`.

For `doVerifiedKycExchange`, implement the method explicitly. If Relay does not
yet return verified-claims metadata, return the same claim values as
`doKycExchange` plus conservative verified-claim metadata only when it can be
represented correctly for eSignet. Do not fake assurance evidence.

## Certificates

`getAllKycSigningCertificates` must reflect the key used to sign KYC/UserInfo
payloads.

V1 signing mechanism:

- Load a configured deployment keystore or JWK keypair for local JWS signing.
- Expose the matching X.509 certificate through
  `getAllKycSigningCertificates`, with a `keyId`/`kid` and algorithm that match
  the JWS header.
- Keep the code path used in tests and the code path used in deployment the
  same. Tests may use generated test-only keys, but not a different signing
  mechanism.

Requirements:

- No private keys committed.
- Tests use generated or test-only keys.
- README documents how to configure keys.
- Empty certificate list is acceptable only if the target response mode
  demonstrably does not require plugin-side signing certificates. Document why.

## Error mapping

Map plugin failures into eSignet exceptions with stable error codes. **Select
the code from the Relay RFC 9457 `code` field, not from the HTTP status.**

Suggested internal error codes:

```text
# Local / challenge faults
relay_auth_invalid_request          # local validation, or Relay release.subject_invalid
relay_auth_unsupported_factor
relay_auth_challenge_failed         # configured challenge verifier rejected the challenge

# Distinguishable Relay outcomes (configuration / operational; surface loudly)
relay_config_profile_not_found      # Relay release.profile_not_found (404)
relay_config_scope_denied           # Relay auth.scope_denied (403)
relay_config_purpose_required       # Relay auth.purpose_required (400)
relay_config_purpose_denied         # Relay auth.purpose_denied (403)
relay_auth_relay_unavailable        # Relay release.source_unavailable (503) or transport timeout

# Collapsed user-facing denial (no sub-reason; never disclose which)
relay_auth_subject_denied           # Relay release.subject_denied

# KYC token
relay_auth_token_invalid
relay_auth_token_expired

# Exchange / packaging
relay_auth_rp_encryption_key_unavailable
relay_kyc_exchange_failed
relay_kyc_signing_failed
relay_kyc_encryption_failed

# M6 packaging / signing (implemented)
relay_kyc_jwe_unsupported           # JWE requested but RP encryption key unavailable -> fail closed
relay_kyc_signing_unavailable       # getAllKycSigningCertificates: signing keystore/key unavailable
```

Guidelines:

- The collapsed `relay_auth_subject_denied` must map to a single generic eSignet
  `KycAuthException` that discloses no underlying condition (not found vs
  ambiguous vs release-denied vs required-claim-missing).
- Configuration-class codes (`relay_config_*`) indicate plugin/deployment
  misconfiguration, not per-user authentication failure, because the plugin
  always sends the same scope, purpose, and profile and pre-validates the
  subject. Treat them as operational errors and make them alertable.
- Authentication failure should not disclose whether the identifier exists when
  doing so would create enumeration risk.
- Logs may include transaction ID and client ID when safe, but not OTPs, raw
  identifiers, bearer tokens, KYC tokens, released attributes, or full Relay
  response bodies.
- Distinguish configuration errors from user authentication failures in tests.

## Security and privacy requirements

- No broad row reads.
- No local persistent cache of released attributes.
- No raw identifiers or attributes in logs.
- No default production static OTP.
- No checked-in secrets, private keys, tokens, or generated keystores.
- Relay credentials must always be sent as `Authorization: Bearer`; do not add
  an `X-API-Key` header path.
- HTTP timeouts required.
- TLS should be assumed for non-local Relay URLs.
- Validate Relay base URL and path configuration.
- Redact secrets in `toString` methods and config logging.
- Keep subject lookup cardinality exactly one from the plugin perspective.
- Fail closed on Relay timeout, collapsed subject denial, and invalid KYC token.

## Tests

Add tests for at least:

- Spring conditional bean loading property value.
- Configuration validation, including missing Relay token and missing HMAC
  secret.
- Supported OTP channel and unsupported channel behavior.
- Static OTP disabled by default.
- Static OTP success in explicit test config.
- `sendOtp` uses non-enumerating public behavior for unknown, ambiguous,
  release-denied, and successful subjects.
- KYC auth success:
  - verifies challenge;
  - calls Relay with only account-check claims;
  - returns a KYC token and PSUT.
- KYC auth failure:
  - wrong challenge -> `relay_auth_challenge_failed`, no Relay call;
  - Relay returns collapsed `release.subject_denied` -> drive the stub with each
    internal scenario (not-found, ambiguous, release-denied, required-claim-
    missing); the plugin produces ONE generic auth failure and discloses no
    sub-reason;
  - Relay `release.source_unavailable` / transport timeout ->
    `relay_auth_relay_unavailable`, fail closed.
- Error mapping is driven by the RFC 9457 `code`, not HTTP status:
  - `release.profile_not_found` (404) -> configuration error, not subject denial;
  - `auth.scope_denied` (403) and `auth.purpose_denied` (403) -> configuration
    errors, distinct from the collapsed user denial;
  - `auth.purpose_required` (400) -> configuration error.
- Claim request filtering:
  - an eSignet-accepted claim not in the profile is omitted before calling Relay
    (Relay is never sent an unknown claim);
  - the request to Relay equals `intersection(accepted, profile)`, with
    protocol-derived claims (`sub`) supplied locally, not requested from Relay.
- KYC token validation:
  - tampering rejected;
  - expiry rejected;
  - RP/client mismatch rejected.
- KYC exchange success:
  - verifies token;
  - requests only consented, profile-filtered claims from Relay;
  - maps claims correctly;
  - includes PSUT-derived subject.
- KYC exchange missing required claim (collapsed `release.subject_denied`).
- JWS packaging uses the configured keystore and exposes the matching
  certificate with a consistent `kid`.
- JWE response mode encrypts to the relying party key when requested, or fails
  closed (`relay_auth_rp_encryption_key_unavailable`) when the key is
  unavailable.
- Logging redaction for failures.
- Certificate list behavior for the selected signing mode.

Use a local HTTP stub for Relay contract tests. The stub must follow
`docs/relay-attribute-release-contract.md`, including returning the same
`release.subject_denied` body for all collapsed scenarios. Do not require a live
Relay deployment for ordinary unit tests.

## README acceptance criteria

The README must explain:

- what the plugin does;
- what it does not do;
- supported eSignet version;
- Java and Maven requirements;
- how to build the JAR;
- how to configure eSignet plugin scanning;
- required Relay endpoint contract;
- that Relay authorization is always `Authorization: Bearer` on the wire;
- that subject-sensitive Relay denials are collapsed and the plugin must not
  surface sub-reasons;
- required secrets and environment variables;
- how to enable static OTP for local demos only;
- KYC token replay limitation within the short TTL;
- how to run tests;
- how to package the JAR for `esignet-with-plugins` or equivalent deployment;
- known limitations and production hardening still required.

Include a minimal eSignet property example:

```properties
mosip.esignet.integration.scan-base-package=io.registry.esignet.relay
mosip.esignet.integration.authenticator=RelayAuthenticationService

registry.relay.base-url=http://registry-relay:8080
registry.relay.attribute-release.profile-id=esignet-civil-userinfo
registry.relay.attribute-release.profile-version=v1
registry.relay.attribute-release.purpose=https://demo.example.gov/purpose/esignet-identity-verification
registry.relay.auth.credential-kind=api_key
registry.relay.auth.bearer-token=${REGISTRY_RELAY_TOKEN}

registry.esignet.auth.supported-factors=OTP
registry.esignet.auth.otp.static-enabled=true
registry.esignet.auth.otp.static-value=111111

registry.esignet.kyc-token.hmac-secret=${REGISTRY_ESIGNET_KYC_TOKEN_SECRET}
registry.esignet.psut.hmac-secret=${REGISTRY_ESIGNET_PSUT_SECRET}
registry.esignet.kyc.signing.keystore-path=${REGISTRY_ESIGNET_KYC_KEYSTORE_PATH}
registry.esignet.kyc.signing.keystore-password=${REGISTRY_ESIGNET_KYC_KEYSTORE_PASSWORD}
registry.esignet.kyc.signing.key-alias=${REGISTRY_ESIGNET_KYC_KEY_ALIAS}
registry.esignet.kyc.signing.key-password=${REGISTRY_ESIGNET_KYC_KEY_PASSWORD}
```

Make it visually clear that static OTP is not production authentication.

## Deliverables

The implementation PR should include:

- Maven Java plugin project.
- `RelayAuthenticationService` implementing eSignet `Authenticator`.
- Typed config and validation.
- Relay attribute release HTTP client.
- Challenge verifier abstraction and static OTP implementation.
- KYC token issuer/verifier.
- Partner-specific subject derivation.
- Claim mapper.
- KYC/UserInfo packager for the target eSignet version.
- Certificate exposure matching the selected packager.
- Tests and test fixtures.
- `docs/relay-attribute-release-contract.md` used by the Relay client tests and
  kept aligned with the Relay-side implementation brief.
- README and docs.

## Open design decisions to document in the PR

Document the decisions made for:

- target eSignet version and exact integration API dependency;
- KYC/UserInfo packaging format and JWS algorithm/`kid` convention;
- key/certificate mechanism;
- local demo authentication mode;
- production authentication extension point;
- Relay failure and enumeration-risk behavior, including reliance on Relay's
  collapsed `release.subject_denied`;
- identifier-echo acceptance: the plugin is a trusted caller using an
  identifier-echo profile (`individual_id == national_id`), so a successful
  release is a subject-existence signal to it, gated behind challenge
  verification and the release scope;
- KYC token replay limitation within TTL;
- whether verified-claims metadata is supported or deferred.

## Definition of done

The work is complete when:

- `mvn test` passes.
- The plugin JAR builds.
- The README shows how to configure eSignet to load the plugin.
- Tests prove the plugin calls Relay's attribute release endpoint rather than a
  row-read API.
- Tests prove the Relay client stub follows
  `docs/relay-attribute-release-contract.md`, including the collapsed
  `release.subject_denied` behavior.
- KYC auth does not release demographic attributes before consent.
- KYC exchange requests only consented, profile-filtered claims.
- Secrets and released attributes are redacted from logs.
- The PR clearly names any remaining integration smoke test that requires
  `registry-lab` or a running eSignet deployment.
