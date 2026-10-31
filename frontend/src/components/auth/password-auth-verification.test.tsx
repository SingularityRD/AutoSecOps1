import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import { ApiError, type UserRead } from "@/client"
import { BasicLoginForm } from "@/components/auth/sign-in"
import { BasicRegistrationForm } from "@/components/auth/sign-up"

const login = jest.fn()
const register = jest.fn()

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({ user: null }),
  useAuthActions: () => ({ login, register, logout: jest.fn() }),
}))

jest.mock("@/components/ui/use-toast", () => ({ toast: jest.fn() }))

jest.mock("next/navigation", () => ({
  useRouter: () => ({ push: jest.fn(), replace: jest.fn() }),
}))

function apiError(status: number, detail: unknown): ApiError {
  return new ApiError(
    { method: "POST", url: "/auth" },
    { url: "/auth", ok: false, status, statusText: "", body: { detail } },
    "error"
  )
}

function fillAndSubmit(button: string) {
  fireEvent.change(screen.getByPlaceholderText("user@company.com"), {
    target: { value: "member@example.com" },
  })
  fireEvent.change(screen.getByPlaceholderText("••••••••••••••••"), {
    target: { value: "a-long-enough-password" },
  })
  fireEvent.click(screen.getByRole("button", { name: button }))
}

function userRead(isVerified: boolean): UserRead {
  return {
    id: "00000000-0000-4000-8000-000000000001",
    email: "member@example.com",
    is_verified: isVerified,
  } as UserRead
}

describe("BasicLoginForm", () => {
  beforeEach(() => login.mockReset())

  it("shows the check-inbox state when the email is unverified", async () => {
    login.mockRejectedValue(apiError(400, "LOGIN_USER_NOT_VERIFIED"))
    render(<BasicLoginForm initialEmail="member@example.com" />)

    fillAndSubmit("Sign In")

    expect(await screen.findByTestId("check-inbox")).toHaveTextContent(
      "member@example.com"
    )
    fireEvent.click(screen.getByRole("button", { name: "Back to sign in" }))
    expect(screen.getByRole("button", { name: "Sign In" })).toBeInTheDocument()
  })

  it("keeps the form for wrong credentials", async () => {
    login.mockRejectedValue(apiError(400, "LOGIN_BAD_CREDENTIALS"))
    render(<BasicLoginForm />)

    fillAndSubmit("Sign In")

    await waitFor(() => expect(login).toHaveBeenCalled())
    expect(screen.queryByTestId("check-inbox")).toBeNull()
  })
})

describe("BasicRegistrationForm", () => {
  beforeEach(() => {
    login.mockReset()
    register.mockReset()
  })

  it("asks an unverified registrant to check their inbox instead of signing in", async () => {
    register.mockResolvedValue(userRead(false))
    render(<BasicRegistrationForm />)

    fillAndSubmit("Create account")

    expect(await screen.findByTestId("check-inbox")).toBeInTheDocument()
    expect(login).not.toHaveBeenCalled()
  })

  it("signs in a registrant that was verified on creation", async () => {
    register.mockResolvedValue(userRead(true))
    login.mockResolvedValue(undefined)
    render(<BasicRegistrationForm />)

    fillAndSubmit("Create account")

    await waitFor(() => expect(login).toHaveBeenCalled())
    expect(screen.queryByTestId("check-inbox")).toBeNull()
  })

  it("explains that self-registration needs email delivery", async () => {
    register.mockRejectedValue(
      apiError(403, {
        code: "self_registration_unavailable",
        message: "Ask an administrator for an invitation.",
      })
    )
    render(<BasicRegistrationForm />)

    fillAndSubmit("Create account")

    expect(
      await screen.findByText("Ask an administrator for an invitation.")
    ).toBeInTheDocument()
  })

  it("shows the password policy reason", async () => {
    register.mockRejectedValue(
      apiError(400, {
        code: "REGISTER_INVALID_PASSWORD",
        reason: "Password must be at least 16 characters long",
      })
    )
    render(<BasicRegistrationForm />)

    fillAndSubmit("Create account")

    expect(
      await screen.findByText("Password must be at least 16 characters long")
    ).toBeInTheDocument()
  })
})
