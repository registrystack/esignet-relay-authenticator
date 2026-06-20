package io.registry.esignet.relay.relay;

/**
 * Internal outcome model for an attribute-release call, derived from the Relay RFC 9457 {@code code}
 * extension field (never from the HTTP status alone).
 *
 * <p>The mapping deliberately mirrors {@code docs/relay-attribute-release-contract.md}:
 *
 * <ul>
 *   <li><b>Distinguishable</b> outcomes each carry a stable {@code code} the plugin may act on. In
 *       normal operation most indicate plugin/deployment misconfiguration (the plugin always sends
 *       the same scope, purpose and profile and pre-validates the subject) rather than a per-user
 *       failure, so they should be surfaced loudly and made alertable.
 *   <li>{@link #SUBJECT_DENIED} is the single <b>collapsed</b> anti-enumeration denial. Relay folds
 *       subject-not-found, ambiguous (&gt;1), release-condition-denied and required-claim-missing
 *       into one public {@code release.subject_denied}. The plugin must not attempt to recover the
 *       sub-reason and must reveal none of it.
 *   <li>{@link #UNAVAILABLE} covers {@code release.source_unavailable} and any transport-level
 *       connect/read timeout or absent response. Fail closed.
 *   <li>{@link #UNKNOWN} is the safe generic fallback for any unmapped or absent {@code code}.
 * </ul>
 */
public enum RelayReleaseError {

  /** {@code release.profile_not_found} (404): unknown/invisible profile or version. Config error. */
  PROFILE_NOT_FOUND("release.profile_not_found"),

  /** {@code auth.scope_denied} (403): caller lacks the release scope. Config/authorization error. */
  SCOPE_DENIED("auth.scope_denied"),

  /** {@code auth.purpose_required} (400): missing {@code Data-Purpose}. Config error. */
  PURPOSE_REQUIRED("auth.purpose_required"),

  /** {@code auth.purpose_denied} (403): purpose not permitted by policy. Config/auth error. */
  PURPOSE_DENIED("auth.purpose_denied"),

  /**
   * {@code release.subject_invalid} (400): bad id type or malformed subject value.
   *
   * <p>The Relay backend additionally (as of the {@code attribute_release.rs} handler reviewed
   * 2026-06-20) emits the generic {@code filter.not_allowed} / {@code filter.invalid_value} codes for
   * subject id-type / value validation instead of {@code release.subject_invalid}. Both are aliased
   * to this outcome in {@link #fromCode(String)} so a misconfigured subject id-type surfaces as an
   * invalid request rather than a generic subject denial, regardless of which code the backend sends.
   */
  SUBJECT_INVALID("release.subject_invalid"),

  /** {@code release.source_unavailable} (503): source read failed. Fail closed. */
  SOURCE_UNAVAILABLE("release.source_unavailable"),

  /**
   * {@code release.subject_denied}: the single collapsed anti-enumeration denial. Do NOT attempt to
   * distinguish or disclose the underlying sub-reason.
   */
  SUBJECT_DENIED("release.subject_denied"),

  /**
   * Transport-level failure (connect/read timeout, no response) or {@link #SOURCE_UNAVAILABLE}-class
   * unavailability. Not tied to a single wire {@code code}.
   */
  UNAVAILABLE(null),

  /** Safe generic fallback for any unknown/unmapped/absent {@code code}. */
  UNKNOWN(null);

  /** Generic filter codes the backend currently emits for subject id-type/value validation. */
  private static final String FILTER_NOT_ALLOWED = "filter.not_allowed";

  private static final String FILTER_INVALID_VALUE = "filter.invalid_value";

  private final String wireCode;

  RelayReleaseError(String wireCode) {
    this.wireCode = wireCode;
  }

  /**
   * @return the Relay RFC 9457 {@code code} this outcome maps from, or {@code null} for the
   *     synthetic {@link #UNAVAILABLE}/{@link #UNKNOWN} outcomes that have no single wire code
   */
  public String wireCode() {
    return wireCode;
  }

  /**
   * Maps a Relay RFC 9457 {@code code} to an internal outcome. Branches on {@code code}, never on the
   * HTTP status. Any unrecognized or {@code null} code maps to {@link #UNKNOWN} (a safe generic
   * failure); the caller turns transport errors into {@link #UNAVAILABLE} separately.
   *
   * @param code the {@code code} extension from the problem document, may be {@code null}
   * @return the matching internal outcome, never {@code null}
   */
  public static RelayReleaseError fromCode(String code) {
    if (code == null) {
      return UNKNOWN;
    }
    String trimmed = code.trim();
    // The backend currently emits the generic filter.* codes for subject id-type/value validation
    // instead of release.subject_invalid; alias them so a bad subject id-type/value is reported as
    // an invalid request rather than a generic subject denial.
    if (FILTER_NOT_ALLOWED.equals(trimmed) || FILTER_INVALID_VALUE.equals(trimmed)) {
      return SUBJECT_INVALID;
    }
    for (RelayReleaseError e : values()) {
      if (e.wireCode != null && e.wireCode.equals(trimmed)) {
        return e;
      }
    }
    return UNKNOWN;
  }
}
