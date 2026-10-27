/**
 * @jest-environment jsdom
 */

import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import type { ReactNode } from "react"
import {
  type CaseReadMinimal,
  type RobotKeyRead,
  type RobotRead,
  robotEdrRevokeRobotKey,
} from "@/client"
import { RobotEdrAccessGate } from "@/components/robot-edr/robot-edr-access"
import { RobotKeysTable } from "@/components/robot-edr/robot-keys-table"
import {
  type FleetRow,
  filterFleetRows,
} from "@/components/robot-edr/robots-fleet"
import { QueryClient, QueryClientProvider } from "@/lib/query"
import {
  robotKeyStatus,
  summarizeRobotFindings,
  summarizeRobotKeys,
} from "@/lib/robodr"

jest.mock("@/client", () => ({
  ...jest.requireActual("@/client"),
  robotEdrRevokeRobotKey: jest.fn(),
}))

jest.mock("@/components/ui/use-toast", () => ({
  toast: jest.fn(),
}))

let mockScopes: Record<string, boolean | undefined> = {}
jest.mock("@/components/auth/scope-guard", () => ({
  useScopeCheck: (scope: string) => mockScopes[scope],
}))

let mockEntitlements = {
  entitled: true,
  isLoading: false,
  hasEntitlementData: true,
}
const mockUseEntitlements = jest.fn()
jest.mock("@/hooks/use-entitlements", () => ({
  useEntitlements: (options: unknown) => {
    mockUseEntitlements(options)
    return {
      hasEntitlement: (key: string) =>
        key === "robot_edr" && mockEntitlements.entitled,
      isLoading: mockEntitlements.isLoading,
      hasEntitlementData: mockEntitlements.hasEntitlementData,
    }
  },
}))

const KEY: RobotKeyRead = {
  id: "11111111-1111-4111-8111-111111111111",
  key_id: "ed25519:0123456789abcdef",
  role: "uplink",
  robot_id: "ugv-001",
  public_key: "a".repeat(64),
  site: null,
  vouches_origin: false,
  revoked_at: null,
  expires_at: null,
  created_by: null,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
}

function robot(overrides: Partial<RobotRead>): RobotRead {
  return {
    id: "r-1",
    robot_id: "ugv-001",
    site: "range-north",
    model: "rover",
    morphology: "wheeled",
    require_finding_signature: false,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    ...overrides,
  }
}

function finding(
  robotId: string,
  overrides: Partial<CaseReadMinimal>,
  lastSeenMs = 1
): CaseReadMinimal {
  return {
    id: `${robotId}-${lastSeenMs}`,
    short_id: "CASE-1",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    summary: "s",
    status: "new",
    priority: "low",
    severity: "low",
    tags: [{ id: "t", name: "robodr", ref: "robodr", color: null }],
    dropdown_values: [],
    num_sub_cases: 0,
    payload: { robodr: { robot_id: robotId, last_seen_ms: lastSeenMs } },
    ...overrides,
  }
}

function withQueryClient(children: ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe("fleet statistics", () => {
  it("groups RoboDR cases per robot", () => {
    const stats = summarizeRobotFindings([
      finding("ugv-001", { severity: "medium" }, 10),
      finding("ugv-001", { severity: "critical", status: "resolved" }, 30),
      finding("ugv-001", { severity: "high", status: "in_progress" }, 20),
      finding("ugv-002", { tags: [] }, 99),
    ])
    expect(stats.get("ugv-001")).toEqual({
      lastSeenMs: 30,
      openCases: 2,
      highestOpenSeverity: "high",
    })
    expect(stats.has("ugv-002")).toBe(false)
  })

  it("summarizes key status", () => {
    const now = Date.parse("2026-06-01T00:00:00Z")
    expect(robotKeyStatus(KEY, now)).toBe("active")
    expect(robotKeyStatus({ ...KEY, revoked_at: "2026-02-01" }, now)).toBe(
      "revoked"
    )
    expect(
      robotKeyStatus({ ...KEY, expires_at: "2026-05-01T00:00:00Z" }, now)
    ).toBe("expired")
    expect(summarizeRobotKeys([], now)).toBe("none")
    expect(
      summarizeRobotKeys([{ ...KEY, revoked_at: "2026-02-01" }], now)
    ).toBe("inactive")
    expect(summarizeRobotKeys([KEY], now)).toBe("active")
  })

  it("filters fleet rows", () => {
    const rows: FleetRow[] = [
      {
        robot: robot({ id: "1", robot_id: "ugv-001" }),
        stats: { lastSeenMs: 1, openCases: 2, highestOpenSeverity: "high" },
        keySummary: "active",
      },
      {
        robot: robot({ id: "2", robot_id: "arm-007", site: "plant-a" }),
        stats: { lastSeenMs: null, openCases: 0, highestOpenSeverity: null },
        keySummary: "none",
      },
    ]
    const ids = (filtered: FleetRow[]) => filtered.map((row) => row.robot.id)
    expect(
      ids(filterFleetRows(rows, { query: "ARM", site: null, status: "all" }))
    ).toEqual(["2"])
    expect(
      ids(filterFleetRows(rows, { query: "", site: "plant-a", status: "all" }))
    ).toEqual(["2"])
    expect(
      ids(
        filterFleetRows(rows, {
          query: "",
          site: null,
          status: "open-findings",
        })
      )
    ).toEqual(["1"])
    expect(
      ids(
        filterFleetRows(rows, {
          query: "",
          site: null,
          status: "no-active-key",
        })
      )
    ).toEqual(["2"])
  })
})

describe("RobotKeysTable", () => {
  beforeEach(() => {
    jest.mocked(robotEdrRevokeRobotKey).mockReset()
  })

  it("revokes a key only after confirmation", async () => {
    const user = userEvent.setup()
    jest.mocked(robotEdrRevokeRobotKey).mockResolvedValue({
      ...KEY,
      revoked_at: "2026-02-01T00:00:00Z",
    } as never)
    render(
      withQueryClient(
        <RobotKeysTable workspaceId="ws-1" keys={[KEY]} canUpdate />
      )
    )

    await user.click(
      screen.getByRole("button", { name: `Revoke key ${KEY.key_id}` })
    )
    expect(
      await screen.findByRole("alertdialog", {
        name: `Revoke key ${KEY.key_id}?`,
      })
    ).toBeInTheDocument()
    expect(robotEdrRevokeRobotKey).not.toHaveBeenCalled()

    await user.click(screen.getByRole("button", { name: "Revoke key" }))
    await waitFor(() =>
      expect(robotEdrRevokeRobotKey).toHaveBeenCalledWith({
        workspaceId: "ws-1",
        keyId: KEY.id,
      })
    )
  })

  it("does not revoke when the confirmation is cancelled", async () => {
    const user = userEvent.setup()
    render(
      withQueryClient(
        <RobotKeysTable workspaceId="ws-1" keys={[KEY]} canUpdate />
      )
    )
    await user.click(
      screen.getByRole("button", { name: `Revoke key ${KEY.key_id}` })
    )
    await user.click(await screen.findByRole("button", { name: "Cancel" }))
    await waitFor(() =>
      expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument()
    )
    expect(robotEdrRevokeRobotKey).not.toHaveBeenCalled()
  })

  it("hides revoke without robot:update and for revoked keys", () => {
    const { rerender } = render(
      withQueryClient(
        <RobotKeysTable workspaceId="ws-1" keys={[KEY]} canUpdate={false} />
      )
    )
    expect(screen.queryByRole("button", { name: /Revoke/ })).toBeNull()
    rerender(
      withQueryClient(
        <RobotKeysTable
          workspaceId="ws-1"
          keys={[{ ...KEY, revoked_at: "2026-02-01T00:00:00Z" }]}
          canUpdate
        />
      )
    )
    expect(screen.queryByRole("button", { name: /Revoke/ })).toBeNull()
    expect(screen.getByText("Revoked")).toBeInTheDocument()
  })
})

describe("RobotEdrAccessGate", () => {
  beforeEach(() => {
    mockScopes = { "robot:read": true }
    mockEntitlements = {
      entitled: true,
      isLoading: false,
      hasEntitlementData: true,
    }
    mockUseEntitlements.mockReset()
  })

  it("renders children when entitled with robot:read", () => {
    render(<RobotEdrAccessGate>Fleet content</RobotEdrAccessGate>)
    expect(screen.getByText("Fleet content")).toBeInTheDocument()
  })

  it("shows the permission-missing state without robot:read", () => {
    mockScopes = { "robot:read": false }
    render(<RobotEdrAccessGate>Fleet content</RobotEdrAccessGate>)
    expect(
      screen.getByText("You don't have access to robots")
    ).toBeInTheDocument()
    expect(screen.queryByText("Fleet content")).toBeNull()
    // No entitlement request for a user who cannot read robots.
    expect(mockUseEntitlements).toHaveBeenCalledWith({ enabled: false })
  })

  it("shows the entitlement-missing state", () => {
    mockEntitlements.entitled = false
    render(<RobotEdrAccessGate>Fleet content</RobotEdrAccessGate>)
    expect(screen.getByText("Upgrade required")).toBeInTheDocument()
    expect(screen.queryByText("Fleet content")).toBeNull()
  })

  it("shows the unknown state when entitlements fail to load", () => {
    mockEntitlements.hasEntitlementData = false
    render(<RobotEdrAccessGate>Fleet content</RobotEdrAccessGate>)
    expect(screen.getByText("Unable to check plan access")).toBeInTheDocument()
  })
})
