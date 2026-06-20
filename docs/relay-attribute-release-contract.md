# Relay attribute release contract (consumed by this plugin)

Page type: contract reference + test-stub source of truth
Status: draft, aligned to the Relay-side handoff brief

## Source of truth and version pin

The canonical contract is owned by the Registry Relay side and lives at:

```text
registry-internal/docs/registry-relay/esignet-identity-attribute-release-spec.md
```

This file is the **plugin-local mirror** used to build the Relay client and its
test stub. Keep it aligned cell-for-cell with the Relay brief, and record the
Relay spec revision you aligned against here so drift is detectable:

```text
Aligned-to: registry-relay esignet-identity-attribute-release-spec.md
Aligned-on: 2026-06-20 (update commit/date when re-syncing)
```

If the Relay side later publishes an OpenAPI fragment for this route, prefer
vendoring that fragment as the stub's schema and validate the stub against it.

## Endpoint

```http
POST /v1/attribute-releases/{profile_id}/versions/{version}/resolve
Authorization: Bearer <api-key-or-oidc-access-token with the release scope>
Data-Purpose: https://demo.example.gov/purpose/esignet-identity-verification
Content-Type: application/json
Accept: application/json
```

- `profile_id` and `version` are **separate path parameters**. Callers pin a
  version by path; Relay does not resolve "latest" in v1.
- Authorization is **always `Authorization: Bearer`** on the wire, for both raw
  API keys and OIDC access tokens. There is no `X-API-Key` transport.
- The required release scope is distinct from generic row reads. Example:
  `civil_registry:identity_release`.
- Purpose is carried in the `Data-Purpose` header when the profile requires it.
- Subject identifiers travel in the POST body, never in the URL or query string.

Discovery (metadata) endpoint:

```http
GET /v1/attribute-releases
```

Returns visible profile metadata (id, version, title, purpose, accepted subject
id types, claim names, which claims are required, media type, release scope). It
does not expose private source table ids/paths or policy internals.

## Request body

```json
{
  "subject": {
    "id_type": "national_id",
    "value": "NID-2001"
  },
  "claims": ["individual_id", "name", "given_name", "family_name", "birthdate"]
}
```

- `subject.id_type` must be an accepted subject id type for the profile.
- `claims` is optional. If omitted, Relay returns the profile's default claim
  set.
- **Relay denies the entire request (V1) if any requested claim is not in the
  profile.** It does not silently omit unknown claims. The plugin must send only
  `intersection(consented claims, profile/config-declared claims)`. Optional
  claim omission is the **plugin's** responsibility, performed before the call.

## Success response

`200 OK`, `application/json`:

```json
{
  "profile_id": "esignet-civil-userinfo",
  "profile_version": "v1",
  "purpose": "https://demo.example.gov/purpose/esignet-identity-verification",
  "claims": {
    "individual_id": "NID-2001",
    "name": "Maria Santos",
    "given_name": "Maria",
    "family_name": "Santos",
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

- The response never includes source fields not declared in the profile.
- The response does not echo the raw subject value except through an explicitly
  released claim. (`individual_id == national_id` here is an intentional
  *identifier-echo profile* choice for a trusted caller.)
- The response carries no unkeyed/public subject hash.

## Error model

Relay returns RFC 9457 problem details with media type
`application/problem+json` and a machine-readable `code` extension field. The
plugin **must branch on `code`** (and `type`), never on HTTP status alone,
because several distinct meanings share a status (e.g. 403 = scope vs purpose;
404 = profile-not-found, not subject-not-found).

The `detail` string is operator-facing and intentionally scrubbed — do **not**
parse it programmatically.

`type` URIs follow the pattern
`https://registry-relay.dev/problems/<area>/<name>` (where `code` is
`<area>.<name>`). Confirm exact `type` strings against Relay's emitted problem
documents; the authoritative discriminator is `code`.

### Distinguishable outcomes

These carry a distinct, stable `code` the plugin may act on. In normal
operation most of these indicate **plugin/deployment misconfiguration** (the
plugin always sends the same scope, purpose and profile and pre-validates the
subject), not a per-user authentication failure — surface them loudly and make
them alertable.

| Relay `code` | HTTP | Meaning | Plugin treatment |
| --- | --- | --- | --- |
| `release.profile_not_found` | 404 | unknown/invisible profile or version | configuration error |
| `auth.scope_denied` | 403 | caller lacks release scope | configuration/authorization error |
| `auth.purpose_required` | 400 | missing `Data-Purpose` | configuration error |
| `auth.purpose_denied` | 403 | purpose not permitted by governed policy | configuration/authorization error |
| `release.subject_invalid` | 400 | bad id type or malformed subject value | invalid request (also catch before sending) |
| `release.source_unavailable` | 503 | source read failed | relay-unavailable, fail closed |

Transport level (no problem document): connect/read timeout or no response →
treat as relay-unavailable, fail closed.

### Collapsed outcome (anti-enumeration)

Relay deliberately collapses subject-sensitive outcomes into a **single** public
denial. The finer distinctions exist only in Relay's audit log and are **never
visible to the plugin**. The plugin must not attempt to distinguish them and
must reveal no sub-reason to eSignet or in logs.

| Relay public `code` | Collapses (internal, audit-only) | Plugin treatment |
| --- | --- | --- |
| `release.subject_denied` | subject not found; subject ambiguous (>1); release condition denied (e.g. deceased/inactive); required claim unavailable | one generic authentication failure |

> Open item to pin with the Relay side: the Relay outcome table does not yet
> specify an HTTP status for the collapsed `release.subject_denied` (every other
> row has one). Record the agreed status here once pinned. Until then, treat any
> `code == release.subject_denied` as the collapsed denial regardless of status.

### Example error bodies

Scope denied:

```json
{
  "type": "https://registry-relay.dev/problems/auth/scope_denied",
  "title": "Scope denied",
  "status": 403,
  "code": "auth.scope_denied",
  "detail": "required scope: civil_registry:identity_release"
}
```

Collapsed subject denial (returned identically for not-found / ambiguous /
release-denied / required-claim-missing):

```json
{
  "type": "https://registry-relay.dev/problems/release/subject_denied",
  "title": "Subject release denied",
  "status": 403,
  "code": "release.subject_denied"
}
```

## Stub requirements

The local Relay stub used by contract tests must:

- accept only `POST .../resolve` with `Authorization: Bearer`, `Data-Purpose`,
  and `Accept: application/json`;
- return the success body above for the happy path;
- emit the **exact** `code`/`type`/status values from the tables above for each
  error;
- return the **same** `release.subject_denied` body for all four internal
  collapsed scenarios, so tests prove the plugin cannot and does not branch on
  the hidden sub-reason;
- reject a request that contains a claim outside the configured profile (proves
  the plugin filtered claims before calling).
