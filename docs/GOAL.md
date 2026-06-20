# Goal: eSignet Relay Authenticator plugin (v1)

Status: complete — M0–M8 delivered; `mvn -B verify` green (125 tests), plugin JAR builds.
Owner: implementer working on branch `claude/admiring-brahmagupta-sw2n04`
Drives: full implementation of this repository

## North star

Ship a self-contained, tested eSignet `1.8.0` Authenticator plugin JAR that:

1. authenticates a person through a pluggable challenge verifier (static OTP for
   demos, real verifier in production), and
2. releases only consented OIDC/UserInfo claims by calling Registry Relay's
   **governed attribute-release endpoint** — never a row-read API — packaging
   the result as signed (JWS) and optionally encrypted (JWE) KYC that eSignet
   accepts.

This goal is the execution contract. The *what* and *why* live in the specs;
this file adds the *how we get there* and the *done bar*.

- Spec: `docs/esignet-relay-authenticator-plugin-spec.md`
- Contract / stub source of truth: `docs/relay-attribute-release-contract.md`

## Definition of done (acceptance)

The work is complete when all of the following hold:

- `mvn test` passes and `mvn -DskipTests package` produces the plugin JAR.
- The authenticator bean loads only when
  `mosip.esignet.integration.authenticator=RelayAuthenticationService`.
- Tests prove the plugin calls the **attribute-release** endpoint, not a
  row-read API.
- Tests prove KYC auth releases no demographic claims before consent, and KYC
  exchange requests only consented, profile-filtered claims.
- Tests prove the collapsed `release.subject_denied` is handled as a single
  generic auth failure with no sub-reason disclosed, and that error mapping
  branches on the RFC 9457 `code`, not HTTP status.
- Tests prove secrets and released attributes are redacted from logs.
- JWS output carries a `kid`/algorithm that matches the certificate returned by
  `getAllKycSigningCertificates`; JWE-on-request encrypts to the RP key or fails
  closed.
- README and `docs/esignet-configuration.md` explain build, eSignet wiring,
  required secrets, static-OTP-is-not-production, and known limitations.
- The PR names any remaining smoke test that needs `registry-lab` or a running
  eSignet.

(Full DoD detail: see the spec's "Definition of done".)

## Scope

In scope: the plugin code, typed config + validation, Relay attribute-release
client, challenge-verifier abstraction + static OTP, KYC token issuer/verifier,
PSUT derivation, claim mapper, self-contained JWS/JWE KYC packager, certificate
exposure, tests + fixtures, a local Relay stub, README/docs, and a CI workflow.

Out of scope (do not build here): the Relay endpoint itself, a generic row-read
client, syncing Relay data into eSignet/MOSIP storage, lab Compose wiring, any
custom OIDC flow outside the Authenticator interface.

## Constraints & guardrails

- Java 21, Maven; `io.mosip.esignet:esignet-integration-api` as `provided`.
- Minimal runtime deps; use `java.net.http.HttpClient` for Relay calls.
- Security: no row reads; no persistent cache of released attributes; no raw
  identifiers/OTPs/tokens/attributes in logs; Relay auth always
  `Authorization: Bearer` (no `X-API-Key`); HTTP timeouts required; fail closed
  on timeout, collapsed denial, and invalid KYC token; no committed secrets,
  private keys, or keystores.
- Contract discipline: keep `docs/relay-attribute-release-contract.md` aligned
  with the Relay-side brief; the stub returns the same `release.subject_denied`
  body for all collapsed scenarios.
- Keep `mvn test` green at the end of every milestone.

## Milestones (each independently verifiable)

All milestones M0–M8 are complete; each landed with `mvn test` green and was
pushed to `claude/admiring-brahmagupta-sw2n04`.

- **M0 — Skeleton + CI.** `pom.xml` (Java 21, `esignet-integration-api`
  provided, JUnit 5/Mockito), package layout, `application.properties`,
  `RelayAuthenticationService` stub implementing `Authenticator` (methods throw
  "not implemented"), GitHub Actions workflow running `mvn -B verify`. Test:
  context/bean-loading conditional property. Gate: compiles, `mvn test` green.
- **M1 — Config + validation.** `RelayAuthenticatorProperties` typed config,
  fail-fast on missing Relay token / HMAC secrets / keystore settings, secret
  redaction in `toString`/logging. Tests: validation success/failure, redaction.
- **M2 — Relay client + stub.** Build request (Bearer, `Data-Purpose`, claim
  filtering, profile/version path), parse success, map errors to internal codes
  by RFC 9457 `code` including the collapsed denial. Local HTTP stub per the
  contract doc. Tests: success, each distinguishable code, collapsed denial,
  claim-filter, timeout → unavailable.
- **M3 — Challenge verifier.** `ChallengeVerifier` abstraction +
  `StaticOtpChallengeVerifier` (disabled by default), `sendOtp`
  non-enumerating, `isSupportedOtpChannel`. Tests: disabled-by-default,
  explicit-enable success, unsupported channel, non-enumerating sendOtp.
- **M4 — KYC token + PSUT.** HS256 KYC token issuer/verifier (bound to
  rp/client/txn/individual, short TTL, `jti`) and PSUT derivation. Tests:
  round-trip, tamper rejected, expiry rejected, rp/client mismatch rejected.
- **M5 — `doKycAuth`.** Wire validate → verify challenge → account-check via
  Relay (`["individual_id"]`) → PSUT → KYC token → `KycAuthResult`; implement
  the `claimsMetadataRequired` overload. Tests: success path + collapsed-denial
  + wrong-challenge (no Relay call).
- **M6 — Claim mapper + KYC packager.** Config-driven mapper (intersection
  filter, scalar types, `$psut` sub), self-contained JWS signer (keystore,
  stable `kid`), JWE-on-request with fail-closed, `getAllKycSigningCertificates`
  matching the signing key. Tests: mapping, JWS+cert agreement, JWE encrypt /
  fail-closed, deterministic test keys.
- **M7 — `doKycExchange` + `doVerifiedKycExchange`.** Verify token → consented
  + profile-filtered claims → Relay → map → package → result; verified-exchange
  defers assurance metadata. Tests: consented-only, PSUT sub, missing-required
  claim, verified path.
- **M8 — README + docs + package.** README acceptance criteria,
  `docs/esignet-configuration.md`, packaging notes for `esignet-with-plugins`.
  Run `mvn test` and `mvn package`; finalize the PR description and open items.

## Verification

- Per milestone: targeted `mvn -q -Dtest=<Class> test`, then full `mvn test`.
- Final: `mvn -B verify` and `mvn -DskipTests package`.
- No live Relay or eSignet deployment is required for any unit/contract test.

## Risks / open items (record decisions in the PR)

- Exact `KycExchangeResult` / DTO shapes for eSignet `1.8.0` — confirm against
  the `provided` dependency before M6/M7.
- RP encryption-key sourcing for JWE — document the mechanism; fail closed if
  unavailable.
- Collapsed `release.subject_denied` HTTP status — **RESOLVED (403)**. Confirmed
  against registry-relay PR #162 (`src/api/attribute_release.rs`); the stub and
  contract doc are pinned to 403. The plugin still branches on `code`, not status.
- KYC-token single-use store deferred (replay within TTL) — documented hardening.

## Working agreement

- Develop on `claude/admiring-brahmagupta-sw2n04`; extend PR #1.
- Conventional, focused commits per milestone; keep the build green.
- Do not touch `registry-relay`, `registry-lab`, `registry-internal`, or MOSIP
  repos.
