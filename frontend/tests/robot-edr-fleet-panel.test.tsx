/**
 * @jest-environment jsdom
 */

import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import type { ReactNode } from "react"
import {
  type FleetApprovalRead,
  type FleetSocKeyRead,
  type FleetTokenIssued,
  type RobotFleetStatus,
  robotEdrApproveRobotProfile,
  robotEdrGetRobotFleetStatus,
  robotEdrIssueRobotEnrollmentToken,
  robotEdrListFleetRevocationLists,
  robotEdrListFleetSocKeys,
  robotEdrListFleetTrustRoots,
  robotEdrSubmitRobotProfileApprovalSignature,
} from "@/client"
import { RobotFleetPanel } from "@/components/robot-edr/robot-fleet-panel"
import { QueryClient, QueryClientProvider } from "@/lib/query"

jest.mock("@/client", () => ({
  ...jest.requireActual("@/client"),
  robotEdrGetRobotFleetStatus: jest.fn(),
  robotEdrListFleetSocKeys: jest.fn(),
  robotEdrListFleetRevocationLists: jest.fn(),
  robotEdrIssueRobotEnrollmentToken: jest.fn(),
  robotEdrApproveRobotProfile: jest.fn(),
  robotEdrListFleetTrustRoots: jest.fn(),
  robotEdrSubmitRobotProfileApprovalSignature: jest.fn(),
}))

jest.mock("@/components/ui/use-toast", () => ({
  toast: jest.fn(),
}))

jest.mock("@/components/copy-button", () => ({
  CopyButton: ({ tooltipMessage }: { tooltipMessage?: string }) => (
    <button type="button">{tooltipMessage ?? "Copy"}</button>
  ),
}))

let mockScopes: Record<string, boolean | undefined> = {}
jest.mock("@/components/auth/scope-guard", () => ({
  useScopeCheck: (scope: string) => mockScopes[scope],
}))

let mockUserId = "user-a"
jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({ user: { id: mockUserId } }),
}))

const DIGEST = `sha256:${"7".repeat(64)}`

const FLEET_KEY: FleetSocKeyRead = {
  id: "k-1",
  kind: "fleet",
  key_id: "ed25519:370ede82195fa32b",
  fingerprint: `sha256:${"1".repeat(64)}`,
  custody: "online",
  status: "active",
  public_key_file: "{}",
  created_by: "user-a",
  activated_by: "user-a",
  created_at: "2026-01-01T00:00:00Z",
  activated_at: "2026-01-01T00:00:00Z",
  retired_at: null,
}

function approval(overrides: Partial<FleetApprovalRead>): FleetApprovalRead {
  return {
    id: "ap-uuid",
    approval_id: "ap-1",
    profile_digest: DIGEST,
    profile_version: 4,
    platform: "ugv-x1",
    status: "pending",
    requested_by: "user-a",
    approved_by: null,
    validity_hours: 24,
    issued_at: null,
    expires_at: null,
    signer_key_id: null,
    created_at: "2026-01-01T00:00:00Z",
    ...overrides,
  }
}

function status(overrides: Partial<RobotFleetStatus> = {}): RobotFleetStatus {
  return {
    enrolled: true,
    workspace: "ws-1",
    enrolled_at: "2026-01-01T00:00:00Z",
    agentd_version: "0.2.0",
    profile_digest: null,
    tokens: [],
    rotations: [
      {
        rotation_id: `rfr1-${"0".repeat(32)}`,
        role: "uplink",
        old_key_id: "ed25519:7bf642b114c6afa2",
        new_key_id: "ed25519:caf521a404f9a7bf",
        status: "open",
        received: true,
        created_at: "2026-01-02T00:00:00Z",
        closed_at: null,
      },
    ],
    drafts: [],
    offer: {
      digest: DIGEST,
      profile_version: 4,
      platform: "ugv-x1",
      updated_at: "2026-01-01T00:00:00Z",
    },
    approvals: [approval({})],
    ring: {
      serial: 3,
      ring: 1,
      target_version: "0.3.0",
      bundle_sha256: null,
      min_version: "0.2.0",
      issued_at: "2026-01-01T00:00:00Z",
      expires_at: "2026-01-08T00:00:00Z",
    },
    ...overrides,
  }
}

function renderPanel() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  const wrap = (children: ReactNode) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
  const rendered = render(
    wrap(
      <RobotFleetPanel
        workspaceId="ws-uuid"
        robotId="robot-uuid"
        robodrRobotId="ugv-001"
      />
    )
  )
  return { ...rendered, client }
}

beforeEach(() => {
  mockScopes = {
    "robot:read": true,
    "robot:update": true,
    "robot:enroll": true,
    "robot:approve": true,
  }
  mockUserId = "user-a"
  jest.mocked(robotEdrGetRobotFleetStatus).mockResolvedValue(status())
  jest.mocked(robotEdrListFleetSocKeys).mockResolvedValue([FLEET_KEY])
  jest.mocked(robotEdrListFleetRevocationLists).mockResolvedValue({
    items: [
      {
        id: "rl-1",
        platform: "ugv-x1",
        serial: 2,
        list_digest: `sha256:${"2".repeat(64)}`,
        signer_key_id: "ed25519:acdd03f52b337b5e",
        signature_checked: true,
        created_at: "2026-01-01T00:00:00Z",
      },
    ],
    next_cursor: null,
    prev_cursor: null,
  } as never)
  jest.mocked(robotEdrListFleetTrustRoots).mockResolvedValue([])
  jest.mocked(robotEdrIssueRobotEnrollmentToken).mockReset()
  jest.mocked(robotEdrApproveRobotProfile).mockReset()
  jest.mocked(robotEdrSubmitRobotProfileApprovalSignature).mockReset()
})

describe("RobotFleetPanel", () => {
  it("shows enrollment, rotation, ring and revocation status", async () => {
    renderPanel()
    expect(
      await screen.findAllByText("0.2.0", { selector: "dd" })
    ).toHaveLength(2)
    expect(screen.getByText("Overlap")).toBeTruthy()
    expect(screen.getByText("1 · Early")).toBeTruthy()
    expect(screen.getByText("ed25519:acdd03f52b337b5e")).toBeTruthy()
    expect(screen.getByText("ed25519:370ede82195fa32b")).toBeTruthy()
  })

  it("issues a token and shows it once with its expiry", async () => {
    const user = userEvent.setup()
    const issued: FleetTokenIssued = {
      id: "t-uuid",
      token_id: "rdt-0001",
      robot_id: "ugv-001",
      site: "lab-1",
      workspace: "ws-1",
      soc_key_id: FLEET_KEY.key_id,
      issued_at: "2026-01-01T00:00:00Z",
      expires_at: "2026-01-02T00:00:00Z",
      consumed_at: null,
      revoked_at: null,
      status: "active",
      token: "rdet1.payload.signature",
    }
    jest.mocked(robotEdrIssueRobotEnrollmentToken).mockResolvedValue(issued)
    renderPanel()
    await user.click(await screen.findByRole("button", { name: /Enroll/ }))
    await user.click(screen.getByRole("button", { name: "Issue token" }))
    const token = (await screen.findByLabelText(
      "Enrollment token"
    )) as HTMLTextAreaElement
    expect(token.value).toBe("rdet1.payload.signature")
    expect(screen.getByText(/shown once/)).toBeTruthy()
    expect(screen.getByText("rdt-0001")).toBeTruthy()
    expect(robotEdrIssueRobotEnrollmentToken).toHaveBeenCalledWith({
      workspaceId: "ws-uuid",
      robotId: "robot-uuid",
      requestBody: { validity_hours: 24 },
    })
  })

  it("hides enrollment without robot:enroll", async () => {
    mockScopes["robot:enroll"] = false
    renderPanel()
    await screen.findByText("Overlap")
    expect(screen.queryByRole("button", { name: /Enroll/ })).toBeNull()
  })

  it("does not let the requester approve their own request", async () => {
    renderPanel()
    const table = await screen.findByRole("table", {
      name: "Profile approvals",
    })
    const approve = within(table).getByRole("button", { name: "Approve" })
    expect((approve as HTMLButtonElement).disabled).toBe(true)
  })

  it("lets a second user approve", async () => {
    const user = userEvent.setup()
    mockUserId = "user-b"
    jest
      .mocked(robotEdrApproveRobotProfile)
      .mockResolvedValue(approval({ status: "signed", approved_by: "user-b" }))
    renderPanel()
    const table = await screen.findByRole("table", {
      name: "Profile approvals",
    })
    await user.click(within(table).getByRole("button", { name: "Approve" }))
    await waitFor(() =>
      expect(robotEdrApproveRobotProfile).toHaveBeenCalledWith({
        workspaceId: "ws-uuid",
        robotId: "robot-uuid",
        approvalId: "ap-uuid",
      })
    )
  })

  it("drops the issued token from the mutation cache when the dialog closes", async () => {
    const user = userEvent.setup()
    jest.mocked(robotEdrIssueRobotEnrollmentToken).mockResolvedValue({
      id: "t-uuid",
      token_id: "rdt-0002",
      robot_id: "ugv-001",
      site: null,
      workspace: "ws-1",
      soc_key_id: FLEET_KEY.key_id,
      issued_at: "2026-01-01T00:00:00Z",
      expires_at: "2026-01-02T00:00:00Z",
      consumed_at: null,
      revoked_at: null,
      status: "active",
      token: "rdet1.secret.token",
    })
    const { client } = renderPanel()
    await user.click(await screen.findByRole("button", { name: /Enroll/ }))
    await user.click(screen.getByRole("button", { name: "Issue token" }))
    await screen.findByLabelText("Enrollment token")
    const cached = () =>
      JSON.stringify(
        client
          .getMutationCache()
          .getAll()
          .map((mutation) => mutation.state.data ?? null)
      )
    expect(cached()).toContain("rdet1.secret.token")
    await user.keyboard("{Escape}")
    await waitFor(() =>
      expect(screen.queryByLabelText("Enrollment token")).toBeNull()
    )
    await waitFor(() => expect(cached()).not.toContain("rdet1.secret.token"))
  })

  it("signs a prepared approval with the offline key's signature", async () => {
    const user = userEvent.setup()
    const prepared = approval({
      status: "prepared",
      approved_by: "user-b",
      signer_key_id: "ed25519:00000000000000aa",
      signing_payload: "eyJmb3JtYXQiOiJ4In0",
      signing_message_hex: "ab".repeat(40),
    })
    jest
      .mocked(robotEdrGetRobotFleetStatus)
      .mockResolvedValue(status({ approvals: [prepared] }))
    jest
      .mocked(robotEdrSubmitRobotProfileApprovalSignature)
      .mockResolvedValue({ ...prepared, status: "signed" })
    renderPanel()
    const table = await screen.findByRole("table", {
      name: "Profile approvals",
    })
    expect(
      within(table).getByText("Waiting for the approval key's signature")
    ).toBeTruthy()
    await user.click(within(table).getByRole("button", { name: "Sign" }))
    const message = (await screen.findByLabelText(
      "Message to sign"
    )) as HTMLTextAreaElement
    expect(message.value).toBe("ab".repeat(40))
    await user.type(screen.getByLabelText("Signature"), "cd".repeat(64))
    await user.click(screen.getByRole("button", { name: "Attach signature" }))
    await waitFor(() =>
      expect(robotEdrSubmitRobotProfileApprovalSignature).toHaveBeenCalledWith({
        workspaceId: "ws-uuid",
        robotId: "robot-uuid",
        approvalId: "ap-uuid",
        requestBody: { signature: "cd".repeat(64) },
      })
    )
  })

  it("does not let the user who registered an approval key activate it", async () => {
    const pendingKey: FleetSocKeyRead = {
      ...FLEET_KEY,
      id: "k-2",
      kind: "approval",
      key_id: "ed25519:00000000000000bb",
      custody: "offline",
      status: "pending",
      created_by: "user-a",
      activated_by: null,
      activated_at: null,
    }
    jest
      .mocked(robotEdrListFleetSocKeys)
      .mockResolvedValue([FLEET_KEY, pendingKey])
    renderPanel()
    const activate = await screen.findByRole("button", { name: "Activate" })
    expect((activate as HTMLButtonElement).disabled).toBe(true)
  })
})
