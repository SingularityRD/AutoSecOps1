import { fireEvent, render, screen } from "@testing-library/react"
import type { LicenseNoticeRead } from "@/client"
import {
  LicenseExpiryBanner,
  licenseNoticeMessage,
} from "@/components/license/license-expiry-banner"
import { useLicenseNotice } from "@/hooks/use-license-notice"

jest.mock("@/hooks/use-license-notice", () => ({
  useLicenseNotice: jest.fn(),
}))

const mockUseLicenseNotice = useLicenseNotice as jest.MockedFunction<
  typeof useLicenseNotice
>

function mockNotice(notice: LicenseNoticeRead | undefined) {
  mockUseLicenseNotice.mockReturnValue({ notice })
}

describe("LicenseExpiryBanner", () => {
  beforeEach(() => {
    window.sessionStorage.clear()
  })

  it("renders nothing for unlicensed installs", () => {
    mockNotice({ level: null })
    const { container } = render(<LicenseExpiryBanner />)
    expect(container).toBeEmptyDOMElement()
  })

  it("renders nothing for users who cannot see the notice", () => {
    mockNotice(undefined)
    const { container } = render(<LicenseExpiryBanner />)
    expect(container).toBeEmptyDOMElement()
  })

  it("warns about upcoming expiry and stays dismissed for the session", () => {
    const notice: LicenseNoticeRead = {
      level: "expiring",
      status: "valid",
      days_remaining: 12,
      expires_at: "2030-01-01T00:00:00Z",
    }
    mockNotice(notice)
    const { unmount } = render(<LicenseExpiryBanner />)

    expect(screen.getByRole("status")).toHaveTextContent("expires in 12 days")

    fireEvent.click(
      screen.getByRole("button", { name: "Dismiss license notice" })
    )
    expect(screen.queryByRole("status")).not.toBeInTheDocument()

    unmount()
    render(<LicenseExpiryBanner />)
    expect(screen.queryByRole("status")).not.toBeInTheDocument()
  })

  it("shows again when the notice level changes", () => {
    mockNotice({ level: "expiring", days_remaining: 3 })
    const { unmount } = render(<LicenseExpiryBanner />)
    fireEvent.click(
      screen.getByRole("button", { name: "Dismiss license notice" })
    )
    unmount()

    mockNotice({ level: "grace", grace_ends_at: "2030-01-15T00:00:00Z" })
    render(<LicenseExpiryBanner />)
    expect(screen.getByRole("status")).toHaveTextContent(
      "Paid features stay on"
    )
  })

  it("describes expired and invalid licenses", () => {
    expect(licenseNoticeMessage({ level: "expired" })).toContain(
      "paid features are off"
    )
    expect(licenseNoticeMessage({ level: "invalid" })).toContain("invalid")
  })
})
