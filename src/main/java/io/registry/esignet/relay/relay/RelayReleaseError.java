package io.registry.esignet.relay.relay;

import java.util.Set;

/** Coarse, value-free Relay outcome with retryability kept separate from membership. */
public enum RelayReleaseError {
  SUBJECT_DENIED,
  UNAVAILABLE;

  private static final Set<String> DENIED_CODES =
      Set.of(
          "consultation.unresolved",
          "consultation.denied",
          "resource.not_found",
          "consultation.invalid_request",
          "request.fields_invalid",
          "request.access_profile_invalid",
          "filter.unknown_field",
          "filter.invalid_value");

  private static final Set<String> AUTHENTICATION_CODES =
      Set.of("auth.missing_credential", "auth.invalid_credential");

  public static RelayReleaseError fromCode(String code) {
    if (code != null && DENIED_CODES.contains(code.trim())) {
      return SUBJECT_DENIED;
    }
    return UNAVAILABLE;
  }

  public static boolean isAuthenticationCode(String code) {
    return code != null && AUTHENTICATION_CODES.contains(code.trim());
  }
}
