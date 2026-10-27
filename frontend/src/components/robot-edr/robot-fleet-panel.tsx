"use client"

import { PlusIcon } from "lucide-react"
import type { ReactNode } from "react"
import { useState } from "react"
import type {
  FleetApprovalRead,
  FleetRevocationRead,
  FleetRotationRead,
  FleetSocKeyKind,
  FleetSocKeyRead,
  FleetTokenRead,
  FleetTrustRootRead,
  RobotFleetStatus,
} from "@/client"
import { useScopeCheck } from "@/components/auth/scope-guard"
import { CopyButton } from "@/components/copy-button"
import { AlertNotification } from "@/components/notifications"
import {
  ROBOT_APPROVE_SCOPE,
  ROBOT_ENROLL_SCOPE,
  ROBOT_TRUST_SCOPE,
  ROBOT_UPDATE_SCOPE,
} from "@/components/robot-edr/robot-edr-access"
import {
  AddTrustRootDialog,
  EnrollRobotDialog,
  OfferProfileDialog,
  PublishRevocationListDialog,
  RegisterApprovalKeyDialog,
  SetRingDialog,
  SignApprovalDialog,
} from "@/components/robot-edr/robot-fleet-dialogs"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { toast } from "@/components/ui/use-toast"
import { useAuth } from "@/hooks/use-auth"
import {
  useActivateFleetSocKey,
  useApproveProfile,
  useCancelProfileApproval,
  useCreateFleetSocKey,
  useFleetRevocationLists,
  useFleetSocKeys,
  useFleetTrustRoots,
  useRequestProfileApproval,
  useRevokeEnrollmentToken,
  useRobotFleetStatus,
} from "@/hooks/use-robot-fleet"
import { getApiErrorDetail } from "@/lib/errors"

const RING_LABELS: Record<number, string> = {
  0: "Canary",
  1: "Early",
  2: "Broad",
}

function shortId(value: string, keep = 10): string {
  return value.length > keep * 2 + 1
    ? `${value.slice(0, keep)}…${value.slice(-6)}`
    : value
}

function when(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString() : "—"
}

function Section({
  id,
  title,
  action,
  children,
}: {
  id: string
  title: string
  action?: ReactNode
  children: ReactNode
}) {
  return (
    <section aria-labelledby={id} className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <h3 id={id} className="text-sm font-medium">
          {title}
        </h3>
        {action}
      </div>
      {children}
    </section>
  )
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[180px_minmax(0,1fr)] gap-3 py-2 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  )
}

function StatusBadge({ label, active }: { label: string; active: boolean }) {
  return (
    <Badge
      variant="outline"
      className={
        active
          ? "border-emerald-500/50 text-emerald-700 dark:text-emerald-300"
          : "text-muted-foreground"
      }
    >
      {label}
    </Badge>
  )
}

function failed(title: string, err: unknown) {
  toast({
    title,
    description: getApiErrorDetail(err) ?? undefined,
    variant: "destructive",
  })
}

/** Props for {@link RobotFleetPanel}. */
export interface RobotFleetPanelProps {
  workspaceId: string
  /** AutoSecOps robot id (UUID). */
  robotId: string
  /** The robot's RoboDR id. */
  robodrRobotId: string
}

/**
 * The robot's `robodr.fleet` lifecycle: enrollment with a single-use token,
 * key rotations, profile drafts, offer and two-person approvals, update ring
 * and the revocation lists of its platform.
 */
export function RobotFleetPanel({
  workspaceId,
  robotId,
  robodrRobotId,
}: RobotFleetPanelProps) {
  const canUpdate = useScopeCheck(ROBOT_UPDATE_SCOPE) === true
  const canEnroll = useScopeCheck(ROBOT_ENROLL_SCOPE) === true
  const canApprove = useScopeCheck(ROBOT_APPROVE_SCOPE) === true
  const canTrust = useScopeCheck(ROBOT_TRUST_SCOPE) === true
  const status = useRobotFleetStatus(workspaceId, robotId)
  const socKeys = useFleetSocKeys(workspaceId)
  const revocations = useFleetRevocationLists(workspaceId)
  const trustRoots = useFleetTrustRoots(workspaceId)
  const [enrollOpen, setEnrollOpen] = useState(false)
  const [offerOpen, setOfferOpen] = useState(false)
  const [ringOpen, setRingOpen] = useState(false)
  const [revocationOpen, setRevocationOpen] = useState(false)
  const [trustRootOpen, setTrustRootOpen] = useState(false)

  if (status.isLoading) {
    return <Skeleton className="h-32 w-full" />
  }
  if (status.error || !status.data) {
    return (
      <AlertNotification
        level="error"
        message={`Error loading the fleet status: ${status.error?.message ?? "unknown error"}`}
      />
    )
  }
  const fleet = status.data
  const platform = fleet.offer?.platform ?? null

  return (
    <div className="space-y-10">
      <Section
        id="robot-enrollment"
        title="Enrollment"
        action={
          canEnroll ? (
            <Button
              variant="outline"
              size="sm"
              className="h-7"
              onClick={() => setEnrollOpen(true)}
            >
              <PlusIcon className="mr-1 size-3.5" />
              Enroll
            </Button>
          ) : null
        }
      >
        <EnrollmentSummary fleet={fleet} />
        <SocKeysSummary
          workspaceId={workspaceId}
          keys={socKeys.data ?? []}
          loading={socKeys.isLoading}
          canEnroll={canEnroll}
          canApprove={canApprove}
        />
        <TokensTable
          workspaceId={workspaceId}
          robotId={robotId}
          tokens={fleet.tokens}
          canEnroll={canEnroll}
        />
      </Section>

      <Section id="robot-key-rotations" title="Key rotations">
        <RotationsTable rotations={fleet.rotations} />
      </Section>

      <Section
        id="robot-profile"
        title="Profile"
        action={
          canUpdate ? (
            <Button
              variant="outline"
              size="sm"
              className="h-7"
              onClick={() => setOfferOpen(true)}
            >
              Offer profile
            </Button>
          ) : null
        }
      >
        <ProfileSummary
          workspaceId={workspaceId}
          robotId={robotId}
          fleet={fleet}
          canApprove={canApprove}
        />
      </Section>

      <Section
        id="robot-ring"
        title="Update ring"
        action={
          canUpdate && fleet.enrolled ? (
            <Button
              variant="outline"
              size="sm"
              className="h-7"
              onClick={() => setRingOpen(true)}
            >
              Set ring
            </Button>
          ) : null
        }
      >
        {fleet.ring ? (
          <dl className="divide-y rounded-md border px-4">
            <Row label="Ring">
              {fleet.ring.ring} · {RING_LABELS[fleet.ring.ring] ?? "Unknown"}
            </Row>
            <Row label="Target version">{fleet.ring.target_version ?? "—"}</Row>
            <Row label="Minimum version">{fleet.ring.min_version ?? "—"}</Row>
            <Row label="Serial">{fleet.ring.serial}</Row>
            <Row label="Expires">{when(fleet.ring.expires_at)}</Row>
          </dl>
        ) : (
          <p className="text-xs text-muted-foreground">
            No ring information published.
          </p>
        )}
      </Section>

      <Section
        id="robot-revocations"
        title="Revocation list"
        action={
          <div className="flex items-center gap-2">
            {canTrust ? (
              <Button
                variant="outline"
                size="sm"
                className="h-7"
                onClick={() => setTrustRootOpen(true)}
              >
                Add trust root
              </Button>
            ) : null}
            {canUpdate ? (
              <Button
                variant="outline"
                size="sm"
                className="h-7"
                onClick={() => setRevocationOpen(true)}
              >
                Publish list
              </Button>
            ) : null}
          </div>
        }
      >
        <RevocationSummary
          platform={platform}
          lists={revocations.data ?? []}
          loading={revocations.isLoading}
        />
        <TrustRootsSummary
          roots={trustRoots.data ?? []}
          loading={trustRoots.isLoading}
        />
      </Section>

      <EnrollRobotDialog
        workspaceId={workspaceId}
        robotId={robotId}
        robodrRobotId={robodrRobotId}
        open={enrollOpen}
        onOpenChange={setEnrollOpen}
      />
      <OfferProfileDialog
        workspaceId={workspaceId}
        robotId={robotId}
        open={offerOpen}
        onOpenChange={setOfferOpen}
      />
      <SetRingDialog
        workspaceId={workspaceId}
        robotId={robotId}
        open={ringOpen}
        onOpenChange={setRingOpen}
      />
      <PublishRevocationListDialog
        workspaceId={workspaceId}
        open={revocationOpen}
        onOpenChange={setRevocationOpen}
      />
      <AddTrustRootDialog
        workspaceId={workspaceId}
        open={trustRootOpen}
        onOpenChange={setTrustRootOpen}
      />
    </div>
  )
}

function EnrollmentSummary({ fleet }: { fleet: RobotFleetStatus }) {
  if (!fleet.enrolled) {
    return (
      <p className="text-xs text-muted-foreground">
        Not enrolled. Issue a token and run robodr-enroll on the robot.
      </p>
    )
  }
  return (
    <dl className="divide-y rounded-md border px-4">
      <Row label="Enrolled">{when(fleet.enrolled_at)}</Row>
      <Row label="RoboDR release">{fleet.agentd_version ?? "—"}</Row>
      <Row label="Workspace label">
        <span className="font-mono text-xs">{fleet.workspace}</span>
      </Row>
      <Row label="Profile at enrollment">
        <span className="font-mono text-xs">
          {fleet.profile_digest ? shortId(fleet.profile_digest, 16) : "—"}
        </span>
      </Row>
    </dl>
  )
}

const SOC_KEY_LABELS: Record<FleetSocKeyKind, string> = {
  fleet: "Fleet key",
  approval: "Approval key",
}

function custodyLabel(key: FleetSocKeyRead): string | null {
  if (key.kind !== "approval") {
    return null
  }
  return key.custody === "offline"
    ? "Offline"
    : "Online (lower assurance: the server can sign approvals)"
}

/**
 * The SOC keys robots must install, with generate, register and activate
 * actions. An approval key is held offline by default and is activated by a
 * user other than the one who registered it.
 */
function SocKeysSummary({
  workspaceId,
  keys,
  loading,
  canEnroll,
  canApprove,
}: {
  workspaceId: string
  keys: readonly FleetSocKeyRead[]
  loading: boolean
  canEnroll: boolean
  canApprove: boolean
}) {
  const { user } = useAuth()
  const createKey = useCreateFleetSocKey(workspaceId)
  const activate = useActivateFleetSocKey(workspaceId)
  const [registerOpen, setRegisterOpen] = useState(false)
  if (loading) {
    return <Skeleton className="h-12 w-full" />
  }
  async function generate(kind: FleetSocKeyKind) {
    try {
      const created = await createKey.mutateAsync({ kind, custody: "online" })
      toast({
        title: `${SOC_KEY_LABELS[kind]} generated`,
        description: created.key_id,
      })
    } catch (err) {
      failed("Failed to generate key", err)
    }
  }
  async function activateKey(key: FleetSocKeyRead) {
    try {
      await activate.mutateAsync(key.id)
      toast({ title: `${SOC_KEY_LABELS[key.kind]} activated` })
    } catch (err) {
      failed("Failed to activate key", err)
    }
  }
  const kinds: FleetSocKeyKind[] = ["fleet", "approval"]
  return (
    <div className="space-y-1 rounded-md border px-4 py-2 text-sm">
      {kinds.map((kind) => {
        const active = keys.find(
          (k) => k.kind === kind && k.status === "active"
        )
        const pending = keys.filter(
          (k) => k.kind === kind && k.status === "pending"
        )
        const allowed = kind === "fleet" ? canEnroll : canApprove
        return (
          <div key={kind} className="space-y-1 py-1">
            <div className="flex items-center justify-between gap-2">
              <span className="text-muted-foreground">
                {SOC_KEY_LABELS[kind]}
              </span>
              {active ? (
                <span className="flex items-center gap-2 font-mono text-xs">
                  {active.key_id}
                  <CopyButton
                    value={active.public_key_file}
                    toastMessage="Public key file copied"
                    tooltipMessage="Copy the public key file robots install"
                  />
                </span>
              ) : (
                <span className="flex items-center gap-2 text-xs text-muted-foreground">
                  Not configured
                  {allowed && kind === "fleet" ? (
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-6"
                      disabled={createKey.isPending}
                      onClick={() => generate(kind)}
                    >
                      Generate
                    </Button>
                  ) : null}
                  {allowed && kind === "approval" && pending.length === 0 ? (
                    <>
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-6"
                        onClick={() => setRegisterOpen(true)}
                      >
                        Register offline key
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6"
                        disabled={createKey.isPending}
                        title="Lower assurance: the server holds the secret"
                        onClick={() => generate(kind)}
                      >
                        Generate online key
                      </Button>
                    </>
                  ) : null}
                </span>
              )}
            </div>
            {active && custodyLabel(active) ? (
              <p className="text-xs text-muted-foreground">
                {custodyLabel(active)}
              </p>
            ) : null}
            {pending.map((key) => {
              const ownKey = kind === "approval" && key.created_by === user?.id
              return (
                <div
                  key={key.id}
                  className="flex items-center justify-between gap-2 text-xs"
                >
                  <span className="font-mono text-muted-foreground">
                    {key.key_id} · pending
                  </span>
                  {allowed ? (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 text-xs"
                      disabled={ownKey || activate.isPending}
                      title={
                        ownKey
                          ? "A second person must activate the approval key you registered"
                          : "Install its public key file on every robot first"
                      }
                      onClick={() => activateKey(key)}
                    >
                      Activate
                    </Button>
                  ) : null}
                </div>
              )
            })}
          </div>
        )
      })}
      <p className="pt-1 text-xs text-muted-foreground">
        The control-plane signing key (robodr_control_plane secret) rotates
        separately: keep the old and new keys listed in the robot&apos;s
        soc_keys and executor soc.keys until every action the old key approved
        has expired, or the robot does not re-arm those actions after a reboot.
      </p>
      <RegisterApprovalKeyDialog
        workspaceId={workspaceId}
        open={registerOpen}
        onOpenChange={setRegisterOpen}
      />
    </div>
  )
}

const TOKEN_STATUS_LABELS: Record<FleetTokenRead["status"], string> = {
  active: "Active",
  consumed: "Used",
  expired: "Expired",
  revoked: "Revoked",
}

function TokensTable({
  workspaceId,
  robotId,
  tokens,
  canEnroll,
}: {
  workspaceId: string
  robotId: string
  tokens: readonly FleetTokenRead[]
  canEnroll: boolean
}) {
  const revoke = useRevokeEnrollmentToken(workspaceId, robotId)
  if (tokens.length === 0) {
    return null
  }
  return (
    <Table aria-label="Enrollment tokens">
      <TableHeader>
        <TableRow>
          <TableHead>Token</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Expires</TableHead>
          <TableHead className="w-0" />
        </TableRow>
      </TableHeader>
      <TableBody>
        {tokens.map((token) => (
          <TableRow key={token.id}>
            <TableCell className="font-mono text-xs">
              {token.token_id}
            </TableCell>
            <TableCell>
              <StatusBadge
                label={TOKEN_STATUS_LABELS[token.status]}
                active={token.status === "active"}
              />
            </TableCell>
            <TableCell className="text-xs">{when(token.expires_at)}</TableCell>
            <TableCell>
              {canEnroll && token.status === "active" ? (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 text-xs"
                  disabled={revoke.isPending}
                  onClick={async () => {
                    try {
                      await revoke.mutateAsync(token.id)
                    } catch (err) {
                      failed("Failed to revoke token", err)
                    }
                  }}
                >
                  Revoke
                </Button>
              ) : null}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

const ROTATION_STATUS_LABELS: Record<FleetRotationRead["status"], string> = {
  open: "Overlap",
  retired: "Retired",
  cancelled: "Cancelled",
}

/** A robot's key rotations: overlap, retired or cancelled. */
export function RotationsTable({
  rotations,
}: {
  rotations: readonly FleetRotationRead[]
}) {
  if (rotations.length === 0) {
    return <p className="text-xs text-muted-foreground">No key rotation yet.</p>
  }
  return (
    <Table aria-label="Key rotations">
      <TableHeader>
        <TableRow>
          <TableHead>Role</TableHead>
          <TableHead>Old key → new key</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Started</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rotations.map((rotation) => (
          <TableRow key={rotation.rotation_id}>
            <TableCell className="text-xs">{rotation.role}</TableCell>
            <TableCell className="font-mono text-xs">
              {rotation.old_key_id} → {rotation.new_key_id}
            </TableCell>
            <TableCell>
              <StatusBadge
                label={ROTATION_STATUS_LABELS[rotation.status]}
                active={rotation.status === "open"}
              />
              {rotation.received ? null : (
                <span className="ml-2 text-xs text-muted-foreground">
                  (never received)
                </span>
              )}
            </TableCell>
            <TableCell className="text-xs">
              {when(rotation.created_at)}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

const APPROVAL_STATUS_LABELS: Record<FleetApprovalRead["status"], string> = {
  pending: "Waiting for a second sign-off",
  prepared: "Waiting for the approval key's signature",
  signed: "Approved",
  cancelled: "Cancelled",
}

function ProfileSummary({
  workspaceId,
  robotId,
  fleet,
  canApprove,
}: {
  workspaceId: string
  robotId: string
  fleet: RobotFleetStatus
  canApprove: boolean
}) {
  const { user } = useAuth()
  const request = useRequestProfileApproval(workspaceId, robotId)
  const approve = useApproveProfile(workspaceId, robotId)
  const cancel = useCancelProfileApproval(workspaceId, robotId)
  const [signing, setSigning] = useState<FleetApprovalRead | null>(null)
  const offer = fleet.offer
  const offerPending = offer
    ? fleet.approvals.some(
        (a) =>
          (a.status === "pending" || a.status === "prepared") &&
          a.profile_digest === offer.digest
      )
    : false

  async function run(title: string, action: () => Promise<unknown>) {
    try {
      await action()
    } catch (err) {
      failed(title, err)
    }
  }

  return (
    <div className="space-y-4">
      {offer ? (
        <dl className="divide-y rounded-md border px-4">
          <Row label="Offered profile">
            <span className="font-mono text-xs">
              {shortId(offer.digest, 16)}
            </span>
          </Row>
          <Row label="Version / platform">
            {offer.profile_version} · {offer.platform}
          </Row>
          <Row label="Offered">{when(offer.updated_at)}</Row>
        </dl>
      ) : (
        <p className="text-xs text-muted-foreground">
          No profile offered. The robot stays in observe mode.
        </p>
      )}
      {offer && canApprove && fleet.enrolled && !offerPending ? (
        <Button
          variant="outline"
          size="sm"
          className="h-7"
          disabled={request.isPending}
          onClick={() =>
            run("Failed to request approval", () =>
              request.mutateAsync({ profile_digest: offer.digest })
            )
          }
        >
          Request enforce approval
        </Button>
      ) : null}
      {fleet.approvals.length > 0 ? (
        <Table aria-label="Profile approvals">
          <TableHeader>
            <TableRow>
              <TableHead>Profile</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Valid until</TableHead>
              <TableHead className="w-0" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {fleet.approvals.map((approval) => {
              const ownRequest = user?.id === approval.requested_by
              return (
                <TableRow key={approval.id}>
                  <TableCell className="font-mono text-xs">
                    v{approval.profile_version}{" "}
                    {shortId(approval.profile_digest)}
                  </TableCell>
                  <TableCell>
                    <StatusBadge
                      label={APPROVAL_STATUS_LABELS[approval.status]}
                      active={approval.status === "signed"}
                    />
                  </TableCell>
                  <TableCell className="text-xs">
                    {when(approval.expires_at)}
                  </TableCell>
                  <TableCell className="whitespace-nowrap">
                    {canApprove && approval.status === "pending" ? (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 text-xs"
                        disabled={ownRequest || approve.isPending}
                        title={
                          ownRequest
                            ? "A second person must approve your request"
                            : undefined
                        }
                        onClick={() =>
                          run("Failed to approve", () =>
                            approve.mutateAsync(approval.id)
                          )
                        }
                      >
                        Approve
                      </Button>
                    ) : null}
                    {canApprove && approval.status === "prepared" ? (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 text-xs"
                        onClick={() => setSigning(approval)}
                      >
                        Sign
                      </Button>
                    ) : null}
                    {canApprove && approval.status !== "cancelled" ? (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 text-xs"
                        disabled={cancel.isPending}
                        onClick={() =>
                          run("Failed to cancel approval", () =>
                            cancel.mutateAsync(approval.id)
                          )
                        }
                      >
                        Cancel
                      </Button>
                    ) : null}
                  </TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      ) : null}
      <SignApprovalDialog
        workspaceId={workspaceId}
        robotId={robotId}
        approval={signing}
        open={signing !== null}
        onOpenChange={(open) => {
          if (!open) {
            setSigning(null)
          }
        }}
      />
      {fleet.drafts.length > 0 ? (
        <div className="space-y-1">
          <p className="text-xs font-medium">Drafts published by the robot</p>
          <ul className="space-y-1 text-xs">
            {fleet.drafts.map((draft) => (
              <li key={draft.id} className="flex items-center gap-2">
                <span className="font-mono">{shortId(draft.digest, 16)}</span>
                <span className="text-muted-foreground">
                  {draft.size} bytes · {when(draft.received_at)}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  )
}

/** The newest revocation list of the robot's platform. */
export function RevocationSummary({
  platform,
  lists,
  loading,
}: {
  platform: string | null
  lists: readonly FleetRevocationRead[]
  loading: boolean
}) {
  if (loading) {
    return <Skeleton className="h-12 w-full" />
  }
  if (!platform) {
    return (
      <p className="text-xs text-muted-foreground">
        The platform is known once a profile is offered.
      </p>
    )
  }
  const current = lists
    .filter((list) => list.platform === platform && !list.withdrawn_at)
    .sort((a, b) => b.serial - a.serial)[0]
  if (!current) {
    return (
      <p className="text-xs text-muted-foreground">
        No revocation list published for {platform}.
      </p>
    )
  }
  return (
    <dl className="divide-y rounded-md border px-4">
      <Row label="Platform">{platform}</Row>
      <Row label="Serial">{current.serial}</Row>
      <Row label="Signed by">
        <span className="font-mono text-xs">{current.signer_key_id}</span>
        {current.signature_checked ? null : (
          <span className="ml-2 text-xs text-muted-foreground">
            (signature not checked by the SOC)
          </span>
        )}
      </Row>
      <Row label="Published">{when(current.created_at)}</Row>
    </dl>
  )
}

/** The trust roots revocation lists must verify under. */
export function TrustRootsSummary({
  roots,
  loading,
}: {
  roots: readonly FleetTrustRootRead[]
  loading: boolean
}) {
  if (loading) {
    return <Skeleton className="h-8 w-full" />
  }
  const active = roots.filter((root) => !root.revoked_at)
  if (active.length === 0) {
    return (
      <p className="text-xs text-muted-foreground">
        No trust root configured: revocation lists cannot be published.
      </p>
    )
  }
  return (
    <ul className="space-y-1 text-xs" aria-label="Trust roots">
      {active.map((root) => (
        <li key={root.id} className="flex items-center gap-2">
          <span className="font-mono">{root.key_id}</span>
          {root.label ? (
            <span className="text-muted-foreground">{root.label}</span>
          ) : null}
        </li>
      ))}
    </ul>
  )
}
