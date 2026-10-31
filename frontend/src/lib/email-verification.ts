import { ApiError } from "@/client"

/** Error detail fastapi-users returns when an unverified account signs in. */
export const LOGIN_USER_NOT_VERIFIED = "LOGIN_USER_NOT_VERIFIED"
/** Error detail for a verification link that is invalid or expired. */
export const VERIFY_USER_BAD_TOKEN = "VERIFY_USER_BAD_TOKEN"
/** Error detail for a verification link whose account is already verified. */
export const VERIFY_USER_ALREADY_VERIFIED = "VERIFY_USER_ALREADY_VERIFIED"
/** Error code for self-registration refused because SMTP is not configured. */
export const SELF_REGISTRATION_UNAVAILABLE = "self_registration_unavailable"

/** Why a verification link could not be used. */
export type VerifyEmailFailure = "invalid" | "already_verified" | "rate_limited"

function getDetail(error: unknown): unknown {
  if (!(error instanceof ApiError)) {
    return undefined
  }
  const body: unknown = error.body
  if (typeof body !== "object" || body === null || !("detail" in body)) {
    return undefined
  }
  return body.detail
}

/**
 * Whether a password sign-in failed only because the email is unverified.
 * The API says so only after the password matched.
 */
export function isEmailNotVerifiedError(error: unknown): boolean {
  return (
    error instanceof ApiError &&
    error.status === 400 &&
    getDetail(error) === LOGIN_USER_NOT_VERIFIED
  )
}

/**
 * Return the explanation when self-registration is disabled because the
 * deployment cannot send verification email, otherwise null.
 */
export function getSelfRegistrationUnavailableMessage(
  error: unknown
): string | null {
  if (!(error instanceof ApiError) || error.status !== 403) {
    return null
  }
  const detail = getDetail(error)
  if (
    typeof detail !== "object" ||
    detail === null ||
    !("code" in detail) ||
    detail.code !== SELF_REGISTRATION_UNAVAILABLE
  ) {
    return null
  }
  if ("message" in detail && typeof detail.message === "string") {
    return detail.message
  }
  return "Self-registration is not available. Ask an administrator for an invitation."
}

/**
 * Classify a failed `POST /auth/verify`, or return null for an unexpected
 * error the caller should surface generically.
 */
export function getVerifyEmailFailure(
  error: unknown
): VerifyEmailFailure | null {
  if (!(error instanceof ApiError)) {
    return null
  }
  if (error.status === 429) {
    return "rate_limited"
  }
  const detail = getDetail(error)
  if (detail === VERIFY_USER_ALREADY_VERIFIED) {
    return "already_verified"
  }
  if (detail === VERIFY_USER_BAD_TOKEN) {
    return "invalid"
  }
  return null
}
