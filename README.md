# eSignet Relay Authenticator

An [eSignet](https://github.com/mosip/esignet) `Authenticator` SPI plugin that
authenticates subjects and releases identity claims through the **Registry
Relay governed attribute-release endpoint** — not through a raw row-read API.

The plugin bridges eSignet's OIDC authentication and KYC-exchange flows to a
purpose-bound, projection-limited Relay *attribute-release profile*. Relay
performs the policy decision (scope, purpose/ODRL, release predicate, claim
projection) and returns only the claims approved for the named profile, mapped
into OIDC/UserInfo shape. The plugin adds eSignet-side concerns: challenge
verification, a short-lived internal KYC token, a partner-specific subject
(PSUT), configuration-driven claim mapping, and self-contained JWS signing of
the UserInfo payload.

---

## What it does

- Implements the eSignet `io.mosip.esignet.api.spi.Authenticator` SPI:
  `doKycAuth`, `doKycExchange`, `doVerifiedKycExchange`, `sendOtp`,
  `isSupportedOtpChannel`, and `getAllKycSigningCertificates`.
- Calls the Relay **attribute-release** endpoint
  (`POST /v1/attribute-releases/{profile_id}/versions/{version}/resolve`) — a
  governed, exactly-one-subject lookup — and never a broad entity/row read.
- Verifies an authentication challenge (a pluggable `ChallengeVerifier`; a
  static-OTP implementation ships for local demos) **before** any Relay call.
- During `doKycAuth`, performs a minimal account-check release
  (default `["individual_id"]`) so **no demographic claims are released before
  consent**.
- Issues a short-lived, HMAC-signed (HS256) internal KYC token bound to
  relying party, client, transaction, and subject.
- Derives a deterministic **partner-specific subject (PSUT)** so relying
  parties never receive the raw national ID.
- During `doKycExchange`, requests only `intersection(eSignet-accepted claims,
  profile-declared claims)` from Relay (optional-claim omission is the plugin's
  job because Relay V1 denies the whole request on any out-of-profile claim),
  maps them to OIDC UserInfo, and returns a **self-contained RS256 JWS**.
- Exposes the matching X.509 signing certificate (same `kid` and algorithm as
  the JWS header) via `getAllKycSigningCertificates`.

## What it does *not* do

- No broad row reads and no local persistent cache of released attributes.
- No `X-API-Key` path — Relay credentials are always sent as
  `Authorization: Bearer` on the wire.
- No production authentication mechanism of its own: the bundled static OTP is
  for local/demo use only (see below). Production deployments supply a real
  `ChallengeVerifier`.
- No JWE encryption of the KYC response (see *Known limitations*): a JWE request
  **fails closed** rather than returning unencrypted data.
- No fabricated identity-assurance metadata in `doVerifiedKycExchange`.

---

## Requirements

| | |
|---|---|
| Target eSignet | **1.8.0** (`io.mosip.esignet:esignet-integration-api:1.8.0`, `provided` scope) |
| Java | **21** |
| Build | **Maven 3.9+** |

eSignet supplies the integration API, Spring, and Jackson at runtime, so those
are `provided` dependencies here.

## Build

```bash
mvn -B verify            # compile, run all tests, build the JAR
mvn -DskipTests package  # build the JAR only
```

The artifact is `target/esignet-relay-authenticator-<version>.jar`.

## Run the tests

```bash
mvn -B test
```

Tests are fully self-contained — they use a JDK `com.sun.net.httpserver`-based
Relay stub (`RelayStubServer`) that follows
[`docs/relay-attribute-release-contract.md`](docs/relay-attribute-release-contract.md),
and generate in-memory test-only signing keys. **No running eSignet, Relay,
`registry-lab`, or network access is required.**

---

## Configuring eSignet to load the plugin

eSignet loads authenticator plugins by package scan plus a bean selector:

```properties
mosip.esignet.integration.scan-base-package=io.registry.esignet.relay
mosip.esignet.integration.authenticator=RelayAuthenticationService
```

The `RelayAuthenticationService` bean (and its collaborator beans) load **only**
when `mosip.esignet.integration.authenticator=RelayAuthenticationService`; any
other value leaves the plugin dormant.

A full property reference and deployment/packaging walkthrough is in
[`docs/esignet-configuration.md`](docs/esignet-configuration.md).

### Minimal eSignet property example

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
# ⚠ LOCAL DEMO ONLY — see "Static OTP" below. Do NOT enable in production.
registry.esignet.auth.otp.static-enabled=true
registry.esignet.auth.otp.static-value=111111

registry.esignet.kyc-token.hmac-secret=${REGISTRY_ESIGNET_KYC_TOKEN_SECRET}
registry.esignet.psut.hmac-secret=${REGISTRY_ESIGNET_PSUT_SECRET}
registry.esignet.kyc.signing.keystore-path=${REGISTRY_ESIGNET_KYC_KEYSTORE_PATH}
registry.esignet.kyc.signing.keystore-password=${REGISTRY_ESIGNET_KYC_KEYSTORE_PASSWORD}
registry.esignet.kyc.signing.key-alias=${REGISTRY_ESIGNET_KYC_KEY_ALIAS}
registry.esignet.kyc.signing.key-password=${REGISTRY_ESIGNET_KYC_KEY_PASSWORD}
```

---

## Required Relay endpoint contract

The plugin expects the governed attribute-release endpoint described in
[`docs/relay-attribute-release-contract.md`](docs/relay-attribute-release-contract.md)
(the source of truth for the Relay client and its test stub). In summary:

- **Endpoint:** `POST /v1/attribute-releases/{profile_id}/versions/{version}/resolve`
- **Authorization:** always `Authorization: Bearer <token>` (both API-key and
  OIDC credential kinds are carried as a bearer token; there is **no**
  `X-API-Key` header path).
- **Request body:** `{ "subject": { "id_type": "...", "value": ... } }` with an
  optional `"claims": [...]`. The body is strict (`deny_unknown_fields`); the
  plugin **omits** the `claims` field entirely when its computed list is empty
  (an explicit empty `claims: []` is a 400). Absent `claims` ⇒ the profile
  default set.
- **Success body:** `{ "profile_id", "profile_version", "claims": {...},
  "source"? }` — there is **no** top-level `purpose` field; `source` is treated
  as optional metadata.
- **Errors:** RFC 9457 `application/problem+json` with a machine-readable
  `code`. The plugin selects its error from the `code`, **not** the HTTP status.

### Collapsed denials — do not surface sub-reasons

Relay deliberately collapses subject-not-found, ambiguous-subject,
release-denied, and required-claim-missing into a single
`release.subject_denied` (HTTP 403) to prevent enumeration. The plugin maps this
to **one** generic `relay_auth_subject_denied` failure and **must not** disclose
which underlying condition occurred. Distinguishable `relay_config_*` codes
(profile-not-found, scope-denied, purpose-required/denied) indicate
plugin/deployment **misconfiguration** and should be treated as alertable
operational errors, not per-user auth failures.

---

## Secrets and environment variables

All secrets come from the environment or a secret manager — **never** committed
and never logged. The validated config redacts them in `toString`. Both HMAC
secrets must be **≥ 32 characters** (high-entropy random) or startup validation
fails; the signing key must be **RSA ≥ 2048 bits**.

| Property | Env var (example) | Purpose |
|---|---|---|
| `registry.relay.auth.bearer-token` | `REGISTRY_RELAY_TOKEN` | Bearer credential for Relay |
| `registry.esignet.kyc-token.hmac-secret` | `REGISTRY_ESIGNET_KYC_TOKEN_SECRET` | HS256 key for the internal KYC token (≥ 32 chars) |
| `registry.esignet.psut.hmac-secret` | `REGISTRY_ESIGNET_PSUT_SECRET` | HMAC key for PSUT derivation (must differ from the KYC token secret; ≥ 32 chars) |
| `registry.esignet.kyc.signing.keystore-path` | `REGISTRY_ESIGNET_KYC_KEYSTORE_PATH` | Path to the RSA signing keystore (PKCS12/JKS, RSA ≥ 2048-bit) |
| `registry.esignet.kyc.signing.keystore-password` | `REGISTRY_ESIGNET_KYC_KEYSTORE_PASSWORD` | Keystore password |
| `registry.esignet.kyc.signing.key-alias` | `REGISTRY_ESIGNET_KYC_KEY_ALIAS` | Signing key alias |
| `registry.esignet.kyc.signing.key-password` | `REGISTRY_ESIGNET_KYC_KEY_PASSWORD` | Signing key password |

No private keys or keystores are committed. See
[`docs/esignet-configuration.md`](docs/esignet-configuration.md) for generating
a signing keystore.

---

## Static OTP is **not** production authentication

> ⚠️ **The bundled static-OTP `ChallengeVerifier` is for local development and
> demos ONLY.** It accepts a fixed configured value and proves nothing about the
> subject. It is **disabled by default** (`registry.esignet.auth.otp.static-enabled=false`)
> and there is **no** default production static OTP value.

For production, provide a real `ChallengeVerifier` bean (e.g. a genuine OTP/IDA
factor). The configuration bean is `@ConditionalOnMissingBean`, so dropping in a
production `ChallengeVerifier` overrides the static one without code changes.

---

## Signing and certificates

- UserInfo/KYC payloads are signed as a **self-contained RS256 JWS** using the
  configured deployment keystore. The JWS header carries a stable `kid` =
  `base64url(SHA-256(RFC 7638 JWK thumbprint))` of the RSA public key.
- `getAllKycSigningCertificates` returns the matching X.509 certificate as PEM
  with the **same** `kid` and algorithm, so eSignet can publish it and relying
  parties can verify signatures.
- The code path used in tests and in deployment is identical; tests inject a
  generated test-only keystore through the production loader.

---

## Error codes

Stable internal codes selected from the Relay RFC 9457 `code` (full table in the
[spec](docs/esignet-relay-authenticator-plugin-spec.md#error-mapping)):

| Code | Meaning |
|---|---|
| `relay_auth_invalid_request` | local validation / `release.subject_invalid` |
| `relay_auth_challenge_failed` | challenge verifier rejected the challenge |
| `relay_auth_subject_denied` | **collapsed** `release.subject_denied` (no sub-reason) |
| `relay_auth_relay_unavailable` | `release.source_unavailable` (503) or transport timeout |
| `relay_config_profile_not_found` / `_scope_denied` / `_purpose_required` / `_purpose_denied` | distinguishable misconfiguration (alertable) |
| `relay_auth_token_invalid` / `relay_auth_token_expired` | KYC token verification |
| `relay_kyc_jwe_unsupported` | JWE requested but RP encryption key unavailable → **fail closed** |
| `relay_kyc_signing_failed` / `relay_kyc_signing_unavailable` | signing/keystore failure |
| `relay_kyc_exchange_failed` | unexpected exchange-flow failure |

---

## Known limitations & production hardening

- **KYC token replay within TTL.** V1 does not keep a persistent single-use
  `jti` store, so a valid KYC token can be replayed within its short TTL if an
  attacker obtains it. Mitigated by a short TTL, binding to rp/client/txn/
  subject, and log redaction. **Production hardening:** add single-use `jti`
  storage.
- **JWE not implemented (fail-closed).** `KycExchangeDto` carries no relying-party
  encryption key and the plugin has no eSignet keymanager API to obtain one, so
  a JWE-mode request fails closed with `relay_kyc_jwe_unsupported` instead of
  returning unencrypted data. Unblocked when the RP encryption key becomes
  available through eSignet runtime/DTO context.
- **Verified claims deferred.** `doVerifiedKycExchange` returns the same claim
  values as `doKycExchange` and does **not** synthesize assurance metadata,
  because Relay V1 returns none. Unblocked when Relay returns verified-claim
  metadata.
- **Static OTP** is demo-only (above).
- **Identifier-echo profile.** The plugin is a trusted caller using an
  identifier-echo profile (`individual_id == national_id`); a successful release
  is therefore a subject-existence signal to the plugin, gated behind challenge
  verification and the release scope.
- **Integration smoke test.** This repository's tests are self-contained. An
  end-to-end smoke test against a running eSignet + a live Relay
  (e.g. via `registry-lab`) is **not** included here and remains a follow-up.

---

## Documentation

- [`docs/esignet-configuration.md`](docs/esignet-configuration.md) — full
  property reference, keystore setup, and `esignet-with-plugins` packaging.
- [`docs/relay-attribute-release-contract.md`](docs/relay-attribute-release-contract.md)
  — the Relay wire contract used by the client and its test stub.
- [`docs/esignet-relay-authenticator-plugin-spec.md`](docs/esignet-relay-authenticator-plugin-spec.md)
  — the full implementation brief and design rationale.
- [`docs/GOAL.md`](docs/GOAL.md) — the milestone execution plan.
