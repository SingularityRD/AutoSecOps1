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

describe("VerifyEmail", () => {
  beforeEach(() => verify.mockReset())

  it("waits for a click before submitting the token", async () => {
    verify.mockResolvedValue({} as Awaited<ReturnType<typeof authVerifyVerify>>)
    render(<VerifyEmail token="signed-token" />)

    expect(verify).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole("button", { name: "Verify email" }))

    await screen.findByText("Email verified")
    expect(verify).toHaveBeenCalledWith({
      requestBody: { token: "signed-token" },
    })
    expect(screen.getByRole("link", { name: "Go to sign in" })).toHaveAttribute(
      "href",
      "/sign-in"
    )
  })

  it("explains an invalid or used link", async () => {
    verify.mockRejectedValue(apiError(400, "VERIFY_USER_BAD_TOKEN"))
    render(<VerifyEmail token="stale" />)

    fireEvent.click(screen.getByRole("button", { name: "Verify email" }))

    await screen.findByText("Link invalid or expired")
  })

  it("tells an already verified user to sign in", async () => {
    verify.mockRejectedValue(apiError(400, "VERIFY_USER_ALREADY_VERIFIED"))
    render(<VerifyEmail token="used" />)

    fireEvent.click(screen.getByRole("button", { name: "Verify email" }))

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
