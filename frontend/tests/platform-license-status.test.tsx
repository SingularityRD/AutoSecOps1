/**
 * @jest-environment jsdom
 */

import { render, screen } from "@testing-library/react"
import type { LicenseRead } from "@/client"
import { PlatformLicenseStatus } from "@/components/admin/platform-license-status"
import { TooltipProvider } from "@/components/ui/tooltip"

let mockLicense: LicenseRead

const DEPLOYMENT_ID = "dep_00000000000000000000000000000001"
const USAGE = { users: 4, workspaces: 2, organizations: 1 }

jest.mock("@/lib/query", () => ({
  useQuery: () => ({ data: mockLicense, isLoading: false, error: null }),
}))

function renderStatus() {
  return render(
    <TooltipProvider>
      <PlatformLicenseStatus />
    </TooltipProvider>
  )
}

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
      usage: USAGE,
      deployment_id: DEPLOYMENT_ID,
    }

    renderStatus()

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
      usage: USAGE,
      deployment_id: DEPLOYMENT_ID,
    }

    renderStatus()

    expect(rowValue("Licensed entitlements")).toHaveTextContent("None")
    expect(rowValue("Included without license")).toHaveTextContent(
      "custom_registry"
    )
  })

  it("shows limits against usage and the deployment ID", () => {
    mockLicense = {
      status: "valid",
      enforced: true,
      plan: "business",
      days_remaining: 12,
      notice: "expiring",
      entitlements: ["git_sync"],
      included_entitlements: ["custom_registry", "workspace_chat"],
      limits: { max_users: 4, max_workspaces: 5 },
      usage: USAGE,
      deployment_id: DEPLOYMENT_ID,
    }

    renderStatus()

    expect(rowValue("Plan")).toHaveTextContent("Business")
    expect(rowValue("Days remaining")).toHaveTextContent("12 days")
    expect(rowValue("Users")).toHaveTextContent("4 of 4")
    expect(rowValue("Users")).toHaveTextContent("Limit reached")
    expect(rowValue("Workspaces")).toHaveTextContent("2 of 5")
    expect(rowValue("Concurrent workflows")).toHaveTextContent("Unlimited")
    expect(screen.getByText(DEPLOYMENT_ID)).toBeInTheDocument()
    expect(screen.getByText("License expires soon")).toBeInTheDocument()
  })

  it("explains a license bound to another deployment", () => {
    mockLicense = {
      status: "invalid",
      enforced: true,
      error: "deployment_mismatch",
      entitlements: [],
      included_entitlements: [],
      usage: USAGE,
      deployment_id: DEPLOYMENT_ID,
      license_deployment_id: "dep_00000000000000000000000000000002",
    }

    renderStatus()

    expect(
      screen.getByText(/bound to a different deployment ID/)
    ).toBeInTheDocument()
  })
})
