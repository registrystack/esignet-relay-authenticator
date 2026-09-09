# Governed BREG lookup contract

The provider uses a deployment-selected BREG lookup. It never accesses
PostgreSQL directly or substitutes a list/search operation.

```http
POST /v1/records/population:lookup?accessProfile=esignet-source&$select=uin,status
Authorization: Bearer <Mint access token>
Content-Type: application/json
Accept: application/json

{"selector":"by-uin","values":{"uin":"<verified identifier>"}}
```

The route, selector name/field, profile and field inventory are operator
configuration. Identity-flow requests cannot alter them. The compiled BREG
package grants only the named lookup and permitted fields. Verified token
claims govern row access; requests cannot create purpose, scope or authority.

Account checks use the minimum configured fields. Post-consent retrieval uses
only the approved, mapped, provisioned intersection. `$select` is nonempty on
every lookup; an empty intersection makes no BREG call.

Success requires a Registry Record envelope with an object at `data.domainData`.
Only requested values from that object become claims. Malformed envelopes fail
closed, absent optional properties are omitted, and metadata and unrequested
values are never released.

Known unresolved/concealed outcomes collapse to one subject refusal.
Authentication, source, audit, timeout and malformed-response failures become a
generic unavailable result. Classification uses the documented problem code,
not HTTP status alone. Errors contain no upstream bodies or values.

## Mint client authentication

```http
POST /token
Content-Type: application/x-www-form-urlencoded
Accept: application/json

grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=<signed assertion>
```

Assertions carry `iss == sub == client_id`, an exact configured audience,
bounded `iat` and `exp`, a fresh `jti`, and the registered key's `kid`. Mint
decides authority from its registration. No scope or client secret is sent.
The default audience is the token endpoint; an explicit audience supports a
native development issuer reached through a container gateway.

Cache expiry is measured from acquisition start and bounded by both Mint's
`expires_in` and the configured maximum. Authentication rejection invalidates
the cache for the next operation without retrying the current lookup.
