import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import type { AdminUserRead } from "@/client"
import { AdminUsersTable } from "@/components/admin/admin-users-table"

const mockVerifyUserEmail = jest.fn<Promise<AdminUserRead>, [string]>()
const mockToast = jest.fn()

const UNVERIFIED: AdminUserRead = {
  id: "00000000-0000-4000-8000-000000000001",
  email: "pending@example.com",
  role: "basic",
  is_active: true,
  is_superuser: false,
  is_verified: false,
}
const VERIFIED: AdminUserRead = {
  ...UNVERIFIED,
  id: "00000000-0000-4000-8000-000000000002",
  email: "verified@example.com",
  is_verified: true,
}

const mockUsers = { current: [UNVERIFIED] }

jest.mock("@/hooks/use-admin", () => ({
  useAdminUsers: () => ({
    users: mockUsers.current,
    createUser: jest.fn(),
    createPending: false,
    promoteToSuperuser: jest.fn(),
    promotePending: false,
    demoteFromSuperuser: jest.fn(),
    demotePending: false,
    deleteUser: jest.fn(),
    deletePending: false,
    resetUserMfa: jest.fn(),
    resetMfaPending: false,
    verifyUserEmail: (userId: string) => mockVerifyUserEmail(userId),
    verifyEmailPending: false,
  }),
}))

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({
    user: { id: "00000000-0000-4000-8000-0000000000ff", isSuperuser: true },
  }),
}))

jest.mock("@/components/ui/use-toast", () => ({
  toast: (...args: unknown[]) => mockToast(...args),
}))

async function openRowActions(): Promise<void> {
  await userEvent.click(screen.getByRole("button", { name: "Open menu" }))
}

describe("AdminUsersTable email verification", () => {
  beforeEach(() => {
    mockVerifyUserEmail.mockReset()
    mockToast.mockReset()
    mockUsers.current = [UNVERIFIED]
  })

  it("marks an unverified user's email verified after confirmation", async () => {
    mockVerifyUserEmail.mockResolvedValue({ ...UNVERIFIED, is_verified: true })
    render(<AdminUsersTable />)

    expect(screen.getByText("Unverified")).toBeInTheDocument()
    await openRowActions()
    await userEvent.click(
      await screen.findByRole("menuitem", { name: "Mark email verified" })
    )

    expect(
      await screen.findByRole("alertdialog", { name: "Mark email verified" })
    ).toBeInTheDocument()
    expect(mockVerifyUserEmail).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole("button", { name: "Mark verified" }))

    await waitFor(() =>
      expect(mockVerifyUserEmail).toHaveBeenCalledWith(UNVERIFIED.id)
    )
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Email verified" })
    )
  })

  it("offers no verify action for a verified user", async () => {
    mockUsers.current = [VERIFIED]
    render(<AdminUsersTable />)

    expect(screen.getByText("Verified")).toBeInTheDocument()
    await openRowActions()

    await screen.findByRole("menu")
    expect(
      screen.queryByRole("menuitem", { name: "Mark email verified" })
    ).toBeNull()
  })
})
