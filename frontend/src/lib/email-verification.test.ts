import { ApiError } from "@/client"
import {
  getSelfRegistrationUnavailableMessage,
  getVerifyEmailFailure,
  isEmailNotVerifiedError,
} from "@/lib/email-verification"

function apiError(status: number, detail: unknown): ApiError {
  return new ApiError(
    { method: "POST", url: "/auth/login" },
    { url: "/auth/login", ok: false, status, statusText: "", body: { detail } },
    "error"
  )
}

describe("isEmailNotVerifiedError", () => {
  it("matches the unverified sign-in failure only", () => {
    expect(
      isEmailNotVerifiedError(apiError(400, "LOGIN_USER_NOT_VERIFIED"))
    ).toBe(true)
    expect(
      isEmailNotVerifiedError(apiError(400, "LOGIN_BAD_CREDENTIALS"))
    ).toBe(false)
    expect(isEmailNotVerifiedError(new Error("LOGIN_USER_NOT_VERIFIED"))).toBe(
      false
    )
  })
})

describe("getSelfRegistrationUnavailableMessage", () => {
  it("returns the server message for the disabled-registration code", () => {
    const error = apiError(403, {
      code: "self_registration_unavailable",
      message: "Ask an administrator.",
    })
    expect(getSelfRegistrationUnavailableMessage(error)).toBe(
      "Ask an administrator."
    )
  })

  it("ignores other forbidden errors", () => {
    expect(
      getSelfRegistrationUnavailableMessage(
        apiError(403, { code: "saml_enforced", message: "x" })
      )
    ).toBeNull()
    expect(getSelfRegistrationUnavailableMessage(apiError(400, "x"))).toBeNull()
  })
})

describe("getVerifyEmailFailure", () => {
  it("classifies verification failures", () => {
    expect(getVerifyEmailFailure(apiError(400, "VERIFY_USER_BAD_TOKEN"))).toBe(
      "invalid"
    )
    expect(
      getVerifyEmailFailure(apiError(400, "VERIFY_USER_ALREADY_VERIFIED"))
    ).toBe("already_verified")
    expect(getVerifyEmailFailure(apiError(429, "Too many"))).toBe(
      "rate_limited"
    )
    expect(getVerifyEmailFailure(apiError(500, "boom"))).toBeNull()
    expect(getVerifyEmailFailure(new Error("x"))).toBeNull()
  })
})
