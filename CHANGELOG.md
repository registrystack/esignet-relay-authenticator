# Changelog

## 0.5.0 (2026-09-14)

- Add an optional companion OIDC UI image from the same pinned eSignet source,
  with an English default, reviewed dependency updates, upstream notices and a
  same-origin proxy restricted to public identity routes. The nonroot runtime
  excludes plugin downloads and query values from access logs.
- Extend candidate and release exports with a separate UI OCI archive, source
  metadata, checksum and attestation. Verify UI routing and the locked production
  dependencies before publication.

## 0.4.0 (2026-09-14)

- Replace the Registry Mint-specific client configuration with an
  issuer-neutral `token_client` using explicit assertion audience, resource,
  scopes, client identity, and key identity. The retired `mint` key is rejected
  rather than aliased.
- Add an opt-in synthetic Mailpit challenge verifier through the existing
  challenge interface. Challenges are bound to the identifier and transaction,
  expire after five minutes, permit at most five attempts, and cannot be reused.
  The pending challenge store is bounded; stored codes are hashed. The verifier
  is disabled by default and does not supply production OTP delivery.

Migrate the former `mint` configuration to `token_client` before upgrading.
The governed BREG lookup, subject continuity and consent contracts are unchanged.

## 0.3.0 (2026-09-09)

This breaking release replaces the unused Java/Maven authenticator with a
native Go provider integrated into eSignet `v2.0.0-beta.1` at
`df0d0e771dae16eb2597b8e5b5dc65e70baa7f86`.

- BREG is the supported backend. A fixed governed lookup and explicit projection
  replace Relay calls; Relay support is deferred.
- Challenge verification precedes account lookup. Fresh consent gates all
  demographic disclosure, including empty and restored flow states.
- Stable pairwise subjects, bounded Mint private-key JWT authentication, and
  JSON-safe encrypted host flow state replace custom KYC tokens.
- eSignet owns signed and encrypted UserInfo. A minimal reviewed source patch
  registers BREG, installs fresh consent, admits two required claim names, and
  redacts OAuth query/referrer values from host access logs.
- Strict YAML and mounted secret files replace Spring properties, signing
  keystores and JAR injection. A synthetic OTP verifier is explicitly opt-in;
  production verification is supplied through the Go interface.
- Verifier cancellation and timeouts preserve dependency-unavailable outcomes.
- The Go module and image source now use the `registrystack` organization.
- Go 1.26.8 and the compatible `golang.org/x/text` 0.39.0 patch are pinned for release validation and builds.
- The CGO-disabled service uses a minimal static distroless runtime. PKCS12 is supported; PKCS11 requires a separate CGO-enabled build.
- Candidate build tooling exports Linux amd64 and arm64 OCI images with pinned
  inputs, source metadata, checksums, SBOM and provenance. Local image loading
  and a matching Solmara BREG journey are documented.

No backwards compatibility with the Java configuration is provided. Historical
release tags and published artifacts remain unchanged. This release does not
deploy hosted services or implement production OTP delivery,
enrollment, wallet login or identity assurance.
