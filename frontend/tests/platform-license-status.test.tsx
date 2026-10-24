/**
 * @jest-environment jsdom
 */

import { render, screen } from "@testing-library/react"
import type { LicenseRead } from "@/client"
import { PlatformLicenseStatus } from "@/components/admin/platform-license-status"

let mockLicense: LicenseRead

jest.mock("@/lib/query", () => ({
  useQuery: () => ({ data: mockLicense, isLoading: false, error: null }),
}))

function rowValue(label: string): HTMLElement {
  const term = screen.getByText(label)
  const value = term.nextElementSibling
  if (!(value instanceof HTMLElement)) {
    throw new Error(`No value for ${label}`)
  }
  return value
}

describe("PlatformLicenseStatus", () => {
  it("lists free baseline entitlements apart from licensed ones", () => {
    mockLicense = {
      status: "valid",
      enforced: true,
      entitlements: ["custom_registry", "git_sync", "workspace_chat"],
      included_entitlements: ["custom_registry", "workspace_chat"],
    }

    render(<PlatformLicenseStatus />)

    const licensed = rowValue("Licensed entitlements")
    expect(licensed).toHaveTextContent("git_sync")
    expect(licensed).not.toHaveTextContent("custom_registry")
    expect(licensed).not.toHaveTextContent("workspace_chat")
    const included = rowValue("Included without license")
    expect(included).toHaveTextContent("custom_registry")
    expect(included).toHaveTextContent("workspace_chat")
    expect(screen.queryByText("Paid entitlements")).not.toBeInTheDocument()
  })

  it("shows no licensed entitlements without a license", () => {
    mockLicense = {
      status: "missing",
      enforced: true,
      entitlements: [],
      included_entitlements: ["custom_registry", "workspace_chat"],
    }

    render(<PlatformLicenseStatus />)

    expect(rowValue("Licensed entitlements")).toHaveTextContent("None")
    expect(rowValue("Included without license")).toHaveTextContent(
      "custom_registry"
    )
  })
})
