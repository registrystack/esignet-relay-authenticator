# Goal: eSignet Relay Authenticator 0.2.0

Deliver a release JAR that integrates eSignet 1.8.0 with Registry Relay V2 using Registry Mint
private-key-JWT client credentials.

## Required outcome

- Challenge verification happens before Mint and Relay.
- Relay access uses `POST /v2/resources/{resource}/lookups/{lookup}` with exactly
  `{"selectors":{"uin":"..."}}`.
- `fields` contains only consented and provisioned properties; optional `accessProfile` selects only
  the configured compiled contract.
- Only `data.domainData` becomes identity claims.
- Mint assertions use exact token-endpoint audience, `iss == sub == client_id`, `kid`, fresh `jti`,
  and bounded times, with no client secret.
- Token reuse is single-flight and bounded by both Mint `expires_in` and operator maximum.
- Unresolved, concealed, and denied outcomes are indistinguishable. Availability and authentication
  outcomes are also generic but retain retryability separation.
- Selectors, tokens, assertions, problem bodies, private key material, and source values remain out of
  logs and errors.
- PSUT, internal KYC token binding, KYC JWS signing, certificate publication, consent filtering, and
  pre-lookup JWE refusal remain intact.
- Maven artifact version is 0.2.0. Release assets include the JAR and `.sha256` checksum.

## Verification

```bash
mvn -B -ntp verify
```

The test suite is self-contained through local Mint and Relay V2 stubs. It pins the threat-sensitive
negative cases and the complete wire shape without requiring a live deployment.
