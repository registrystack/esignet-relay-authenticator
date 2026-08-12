# eSignet Relay Authenticator plugin specification

## Version and scope

This specification defines `io.registry.esignet:esignet-relay-authenticator:0.2.0` for eSignet 1.8.0
and Java 21. It replaces the retired Relay V1 integration with Registry Relay V2 and Registry Mint.

The plugin owns:

- eSignet `Authenticator` SPI adaptation
- challenge sequencing
- Registry Mint client authentication
- one Relay V2 lookup client
- consent and provisioned-property filtering
- internal KYC token and PSUT derivation
- UserInfo mapping and KYC JWS signing

Registry Mint owns OAuth client registration and token authority. Relay owns access-profile selection,
verified-claim authorization, source lookup, disclosure, audit, and value-free problem responses.

## eSignet SPI and runtime posture

The Spring component is conditional on
`mosip.esignet.integration.authenticator=RelayAuthenticationService` and explicitly implements:

```java
KycAuthResult doKycAuth(String relyingPartyId, String clientId, KycAuthDto request);
KycAuthResult doKycAuth(String relyingPartyId, String clientId,
        boolean claimsMetadataRequired, KycAuthDto request);
KycExchangeResult doKycExchange(String relyingPartyId, String clientId,
        KycExchangeDto request);
KycExchangeResult doVerifiedKycExchange(String relyingPartyId, String clientId,
        VerifiedKycExchangeDto request);
SendOtpResult sendOtp(String relyingPartyId, String clientId, SendOtpDto request);
boolean isSupportedOtpChannel(String channel);
List<KycSigningCertificateData> getAllKycSigningCertificates();
```

The Maven artifact keeps the eSignet integration API, Spring, and Jackson in `provided` scope so the
plugin shares the eSignet runtime's copies. Main code uses JDK HTTP and cryptography. Bouncy Castle is
test-only for in-memory certificate fixtures.

## Trust boundaries and invariants

### Challenge before lookup

An invalid, unsupported, absent, or disabled challenge stops before Mint token acquisition and Relay
source access. This sequencing prevents subject membership checks before eSignet authentication.

### Fixed lookup shape

The only subject lookup is:

```text
POST /v2/resources/{resource}/lookups/{lookup}
```

The body is exactly:

```json
{"selectors":{"uin":"<verified subject>"}}
```

The selector never appears in the URL or logs. The query contains an explicit, non-empty `fields`
parameter and optionally `accessProfile`. There are no caller purpose, scope, filter, or policy hints.

### Disclosure monotonicity

`registry.relay.default-claims` is the closed provisioned property inventory.

- Authentication requests use the configured account-check list, which is a non-empty subset of the
  inventory.
- Exchange requests map accepted eSignet claims to Relay properties, exclude `$psut`, de-duplicate in
  stable order, and intersect with the inventory.
- An empty exchange intersection skips Relay. The client never omits `fields` to request profile
  defaults.
- The response mapper reads only `data.domainData` and cannot map Relay core metadata or `meta` into
  UserInfo.

### Registry Mint private-key JWT

The OAuth request contains only `grant_type=client_credentials`, the RFC 7523 client assertion type,
and `client_assertion`. There is no client secret or requested scope.

The assertion uses JDK `SHA256withRSA` and a secret-provided private JWK. It requires RSA 2048 bits or
stronger, `alg=RS256`, and `kid`. Its payload has exactly:

- `iss == sub == registry.mint.client-id`
- `aud == registry.mint.token-endpoint`, exact string equality
- `iat` at assertion construction time
- `exp = iat + configured lifetime`, with lifetime 1 through 300 seconds
- a fresh UUID `jti` per assertion

The corresponding public key and authority are Mint-side registration state. Assertion content does
not grant authority.

### Token lifetime and secret handling

Token acquisition is synchronized, so concurrent cache misses produce one Mint request. A cached
token is usable only before `acquisition_start + min(expires_in, configured_maximum)`. Network delay
therefore shortens, never extends, the effective cache lifetime. Relay authentication rejection
clears the cache. The next operation may mint again; the rejected lookup is not automatically
replayed.

Private JWK rendering is redacted. Token buffers and form bytes are cleared on replacement/use where
the JDK API permits. Selectors, assertions, tokens, problem bodies, response values, private key
members, and source values never enter application logs or exceptions.

### Non-enumerating failures

Relay problem `code`, not HTTP status, selects one of two public eSignet outcomes:

| Internal outcome | eSignet code | Retryability |
|---|---|---|
| unresolved, concealed, denied, fixed-contract validation | `relay_auth_subject_denied` | non-retryable |
| Mint failure, Relay authentication, source/audit/service failure, timeout, malformed/unknown response, transport | `relay_auth_relay_unavailable` | retryable |

Unknown 404 responses are unavailable rather than subject denial. This ensures HTTP status alone
cannot create a membership oracle. Hidden Relay causes within a known denial code are never recovered
or logged.

## eSignet flows

### `doKycAuth`

1. Validate relying party, client, transaction, subject, and challenge presence.
2. Verify challenge.
3. Call Relay with the account-check property list.
4. Derive PSUT using independent HMAC key material.
5. Issue a short-lived internal KYC token bound to relying party, client, transaction, UIN, subject-id
   type, and authentication methods.
6. Return the KYC token and PSUT. Optional claims metadata contains names only.

No demographic claim is requested before consent when the account-check list remains the default
`individual_id`.

The internal compact HS256 token contains `iss=esignet-relay-authenticator`,
`aud=esignet-kyc-exchange`, the subject and `sid`, relying party, OIDC client, transaction, `amr`,
`iat`, `exp`, and `jti`. Exchange verifies the signature, expiry, relying party, client, transaction,
and request subject when present. It contains no demographic claims.

PSUT is deterministic for one relying-party/client/subject tuple:

```text
base64url(HMAC-SHA256(
  psut_secret,
  relyingPartyId + "|" + clientId + "|" + subjectIdType + "|" + subjectValue
))
```

The PSUT key is independent from the internal KYC-token key. The raw UIN is never returned as OIDC
`sub`.

### `doKycExchange`

1. Validate request.
2. Verify the internal KYC token before Mint or Relay.
3. Reject JWE before Mint or Relay because the target eSignet SPI does not provide the RP encryption
   key needed to satisfy it.
4. Take the subject only from the verified KYC token.
5. Compute the consented, mapped, provisioned Relay property intersection.
6. Skip Relay for an empty intersection, otherwise perform the V2 lookup.
7. Derive PSUT and map only returned `domainData` values accepted by eSignet.
8. Sign UserInfo as a compact self-contained RS256 JWS.

The claim map is configuration-driven. `$psut` is a reserved local source token, scalar Relay JSON
types are preserved, absent properties are omitted, and missing civil attributes are never
fabricated.

### `doVerifiedKycExchange`

Runs the same path. It does not fabricate verification or assurance metadata absent from Relay's
response.

### OTP and certificates

`sendOtp` delegates to the configured `ChallengeVerifier` and preserves its non-enumerating public
shape. The bundled static verifier is disabled by default and is never suitable for production.

`getAllKycSigningCertificates` returns the X.509 certificate matching the RS256 KYC signing key. Its
key identifier matches the JWS header.

## Configuration validation

Startup fails with a value-free list of property names when:

- Relay/Mint URLs are absent or invalid
- resource, lookup, accept type, provisioned claims, client id, or private JWK are absent
- the Mint JWK is not a private RS256 RSA CRT JWK with `kid` and 2048-bit modulus
- assertion or cache bounds are invalid
- account-check claims are not a non-empty subset of provisioned claims
- KYC-token or PSUT keys are absent, short, or equal
- required KYC signing keystore settings are absent

Full properties are defined in `docs/esignet-configuration.md`.

## Tests required for release

- challenge failure produces no Mint or Relay request
- exact Relay path, query, headers, selector body, and `data.domainData` projection
- no V1 request member or endpoint
- exact Mint form with no secret/scope
- assertion signature, audience, identity equality, `kid`, fresh `jti`, and bounded time claims
- cache bounded independently by `expires_in` and operator maximum
- concurrent misses single-flight
- consent and account-check field minimization
- unresolved/concealed/denied collapse independent of HTTP status
- authentication and availability failures remain generic and retryable
- malformed success/problem bodies fail closed without value release
- PSUT, internal KYC token binding, JWS signing, certificate matching, and pre-lookup JWE refusal
- Maven `verify` produces the 0.2.0 JAR

The release workflow publishes the JAR and a SHA-256 checksum under the same tag-derived version.
