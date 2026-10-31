import { fireEvent, render, screen } from "@testing-library/react"
import { ApiError, authVerifyRequestToken } from "@/client"
import { CheckInbox } from "@/components/auth/check-inbox"

jest.mock("@/client", () => ({
  ...jest.requireActual("@/client"),
  authVerifyRequestToken: jest.fn(),
}))

const requestToken = jest.mocked(authVerifyRequestToken)

describe("CheckInbox", () => {
  beforeEach(() => requestToken.mockReset())

  it("resends to the given address without revealing account state", async () => {
    requestToken.mockResolvedValue(undefined)
    render(<CheckInbox email="member@example.com" />)

    expect(screen.getByText("member@example.com")).toBeInTheDocument()
    fireEvent.click(
      screen.getByRole("button", { name: "Resend verification email" })
    )

    await screen.findByText(
      "If your account still needs verification, a new email is on its way."
    )
    expect(requestToken).toHaveBeenCalledWith({
      requestBody: { email: "member@example.com" },
    })
  })

  it("explains a rate-limited resend", async () => {
    requestToken.mockRejectedValue(
      new ApiError(
        { method: "POST", url: "/auth/request-verify-token" },
        {
          url: "/auth/request-verify-token",
          ok: false,
          status: 429,
          statusText: "Too Many Requests",
          body: { detail: "Too many requests. Try again later." },
        },
        "error"
      )
    )
    render(<CheckInbox email="member@example.com" />)

    fireEvent.click(
      screen.getByRole("button", { name: "Resend verification email" })
    )

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Too many requests"
    )
  })

  it("offers a way back when given one", () => {
    const onBack = jest.fn()
    render(<CheckInbox email="member@example.com" onBack={onBack} />)

    fireEvent.click(screen.getByRole("button", { name: "Back to sign in" }))

    expect(onBack).toHaveBeenCalled()
  })
})
