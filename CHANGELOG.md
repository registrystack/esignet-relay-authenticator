# Candidate changes

## 0.3.0 candidate

This breaking candidate replaces the unused Java/Maven authenticator with a
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
- Candidate build tooling exports Linux amd64 and arm64 OCI images with pinned
  inputs, source metadata, checksums, SBOM and provenance. Local image loading
  and a matching Solmara BREG journey are documented.

No backwards compatibility with the Java configuration is provided. Historical
release tags and published artifacts remain unchanged. This candidate does not
publish images, deploy hosted services, implement production OTP delivery,
enrollment, wallet login or identity assurance.
