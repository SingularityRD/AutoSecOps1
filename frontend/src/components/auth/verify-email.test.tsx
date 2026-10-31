import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import { ApiError, authVerifyVerify } from "@/client"
import { VerifyEmail } from "@/components/auth/verify-email"

jest.mock("@/client", () => ({
  ...jest.requireActual("@/client"),
  authVerifyVerify: jest.fn(),
}))

const verify = jest.mocked(authVerifyVerify)

function apiError(status: number, detail: unknown): ApiError {
  return new ApiError(
    { method: "POST", url: "/auth/verify" },
    {
      url: "/auth/verify",
      ok: false,
      status,
      statusText: "",
      body: { detail },
    },
    "error"
  )
}

const PASSWORD = "a-long-enough-password"

function fillPasswords(password = PASSWORD, confirm = password) {
  fireEvent.change(screen.getByLabelText("Password"), {
    target: { value: password },
  })
  fireEvent.change(screen.getByLabelText("Confirm password"), {
    target: { value: confirm },
  })
  fireEvent.click(screen.getByRole("button", { name: "Verify email" }))
}

describe("VerifyEmail", () => {
  beforeEach(() => verify.mockReset())

  it("submits the token only with the password the user sets", async () => {
    verify.mockResolvedValue({} as Awaited<ReturnType<typeof authVerifyVerify>>)
    render(<VerifyEmail token="signed-token" />)

    expect(verify).not.toHaveBeenCalled()
    fillPasswords()

    await screen.findByText("Email verified")
    expect(verify).toHaveBeenCalledWith({
      requestBody: { token: "signed-token", password: PASSWORD },
    })
    expect(screen.getByRole("link", { name: "Go to sign in" })).toHaveAttribute(
      "href",
      "/sign-in"
    )
  })

  it("does not submit mismatched passwords", async () => {
    render(<VerifyEmail token="signed-token" />)

    fillPasswords(PASSWORD, "something-else-entirely")

    await screen.findByText("Passwords do not match")
    expect(verify).not.toHaveBeenCalled()
  })

  it("shows a refused password on the field and keeps the form", async () => {
    verify.mockRejectedValue(
      apiError(400, {
        code: "VERIFY_USER_INVALID_PASSWORD",
        reason: "Password is too common",
      })
    )
    render(<VerifyEmail token="signed-token" />)

    fillPasswords()

    await screen.findByText("Password is too common")
    expect(
      screen.getByRole("button", { name: "Verify email" })
    ).toBeInTheDocument()
  })

  it("explains an invalid or used link", async () => {
    verify.mockRejectedValue(apiError(400, "VERIFY_USER_BAD_TOKEN"))
    render(<VerifyEmail token="stale" />)

    fillPasswords()

    await screen.findByText("Link invalid or expired")
  })

  it("tells an already verified user to sign in", async () => {
    verify.mockRejectedValue(apiError(400, "VERIFY_USER_ALREADY_VERIFIED"))
    render(<VerifyEmail token="used" />)

    fillPasswords()

    await waitFor(() =>
      expect(screen.getByText("Already verified")).toBeInTheDocument()
    )
  })

  it("treats a link without a token as invalid", () => {
    render(<VerifyEmail token={null} />)

    expect(screen.getByText("Link invalid or expired")).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Verify email" })).toBeNull()
  })
})
