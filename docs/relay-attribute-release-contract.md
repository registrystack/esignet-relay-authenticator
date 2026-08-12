# Relay V2 lookup contract used by eSignet

This file is the wire-contract source for `RelayAttributeReleaseClient` and its local test stub.

## Operation

```http
POST /v2/resources/{resource}/lookups/{lookup}?fields=individual_id,name&accessProfile=esignet
Authorization: Bearer <Registry Mint access token>
Content-Type: application/json
Accept: application/json

{"selectors":{"uin":"NID-2001"}}
```

Rules:

- `resource` and `lookup` are deployment configuration and are path-segment encoded.
- The body has exactly one top-level member, `selectors`, and exactly the lookup selector required by
  this integration, `uin`.
- `fields` is always explicit and non-empty. Its entries have already been reduced to the
  consented, mapped, provisioned property intersection.
- `accessProfile` is included only when `registry.relay.access-profile` is configured. It selects a
  compiled Relay access profile and cannot widen `fields`.
- No selector, purpose, scope, credential, or policy hint is accepted from the eSignet caller.
- There is no `Data-Purpose` header. Relay derives purpose and other authority only from verified
  access-token claims.

## Success

Relay V2 returns a document envelope. The plugin consumes only `data.domainData`:

```json
{
  "data": {
    "registryIdentifier": "civil-registry",
    "recordIdentifier": "opaque-record",
    "revisionIdentifier": "revision",
    "lifecycleState": "active",
    "schemaReference": "https://example.test/schema",
    "semanticModelReference": "https://example.test/model",
    "authorityIdentifier": "civil-authority",
    "recordedAt": "2026-08-12T00:00:00Z",
    "domainData": {
      "individual_id": "NID-2001",
      "name": "Maria Santos"
    }
  },
  "meta": {
    "accessProfile": "esignet"
  }
}
```

Core record fields and `meta` are never mapped into UserInfo. A 200 response without an object at
`data.domainData` fails closed as unavailable and releases nothing.

## Problems and non-enumeration

Relay problems are RFC 9457 `application/problem+json` documents with a stable `code`. The client
branches on `code`, not HTTP status.

Generic non-retryable subject denial:

- `consultation.unresolved`
- `resource.not_found`
- `consultation.denied`
- closed request/profile validation codes that can arise from the fixed integration contract

Generic retryable unavailable:

- `auth.missing_credential`
- `auth.invalid_credential`
- `source.unavailable`
- `audit.unavailable`
- `service.not_ready`
- `internal.timeout`
- internal, rate-limit, unknown, malformed-problem, and transport failures

Relay authentication errors invalidate the cached token, allowing the next eSignet attempt to obtain
a fresh token. The current lookup is not replayed automatically.

The stub deliberately varies HTTP status independently of problem code to prove that status alone
does not classify subject membership. It never returns a hidden not-found, ambiguity, denial, source
value, selector, token, or problem body through exceptions or logs.

## Registry Mint prerequisite

Before the first lookup and after cache expiry/invalidation, the plugin sends to Mint's published
`token_endpoint`, whose current Registry Mint path is exactly `/token`:

```http
POST /token
Content-Type: application/x-www-form-urlencoded
Accept: application/json

grant_type=client_credentials&
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&
client_assertion=<signed JWT>
```

There is no `client_secret` and no caller-selected scope. Mint assigns authority from its registered
client. The assertion header is `{alg:"RS256",typ:"JWT",kid:"..."}`. Its claims are exactly:

- `iss` and `sub`, both equal to `registry.mint.client-id`
- `aud`, exactly equal to `registry.mint.token-endpoint`
- bounded `iat` and `exp`, with a configured lifetime of 1 through 300 seconds
- a new non-empty `jti` for every assertion

Mint success is `{"access_token":"...","token_type":"Bearer","expires_in":...}`. The cache deadline
is calculated from the acquisition start and is the smaller of positive `expires_in` and the
configured maximum, so network time can only shorten the effective cache lifetime.
