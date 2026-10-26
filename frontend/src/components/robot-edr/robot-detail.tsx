"use client"

import { ArrowLeftIcon, PlusIcon, RadarIcon } from "lucide-react"
import Link from "next/link"
import type { ReactNode } from "react"
import { useState } from "react"
import { ApiError, type CaseReadMinimal } from "@/client"
import { useScopeCheck } from "@/components/auth/scope-guard"
import { CaseBadge } from "@/components/cases/case-badge"
import { SEVERITIES, STATUSES } from "@/components/cases/case-categories"
import { CenteredSpinner } from "@/components/loading/spinner"
import { AlertNotification } from "@/components/notifications"
import {
  ROBOT_READ_SCOPE,
  ROBOT_UPDATE_SCOPE,
  RobotEdrAccessGate,
} from "@/components/robot-edr/robot-edr-access"
import { AddRobotKeyDialog } from "@/components/robot-edr/robot-edr-dialogs"
import { RobotKeysTable } from "@/components/robot-edr/robot-keys-table"
import { Button } from "@/components/ui/button"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Skeleton } from "@/components/ui/skeleton"
import {
  useRobodrCase,
  useRobot,
  useRobotFindings,
  useRobotKeys,
} from "@/hooks/use-robot-edr"
import { caseFieldText, formatEpochMs, parseRobodrPayload } from "@/lib/robodr"
import { useWorkspaceId } from "@/providers/workspace-id"

function MetaRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[180px_minmax(0,1fr)] gap-3 py-2 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  )
}

/** Props for {@link RobotDetail}. */
export interface RobotDetailProps {
  /** AutoSecOps robot id (UUID) from the route. */
  robotId: string
}

/** Robot detail page, behind the Robot EDR access gate. */
export function RobotDetail({ robotId }: RobotDetailProps) {
  return (
    <RobotEdrAccessGate>
      <RobotDetailContent robotId={robotId} />
    </RobotEdrAccessGate>
  )
}

function RobotDetailContent({ robotId }: RobotDetailProps) {
  const workspaceId = useWorkspaceId()
  const canRead = useScopeCheck(ROBOT_READ_SCOPE) === true
  const canUpdate = useScopeCheck(ROBOT_UPDATE_SCOPE) === true
  const canReadCases = useScopeCheck("case:read") === true
  const robot = useRobot(workspaceId, robotId, { enabled: canRead })
  const keys = useRobotKeys(workspaceId, { robotId, enabled: canRead })
  const findings = useRobotFindings(workspaceId, robot.data?.robot_id, {
    enabled: canReadCases,
  })
  const latest = findings.data?.items[0] ?? null
  const latestCase = useRobodrCase(workspaceId, latest?.id)
  const [addKeyOpen, setAddKeyOpen] = useState(false)
  const backLink = (
    <Link
      href={`/workspaces/${workspaceId}/robots`}
      className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
    >
      <ArrowLeftIcon className="size-3.5" aria-hidden />
      All robots
    </Link>
  )

  if (robot.isLoading) {
    return <CenteredSpinner />
  }
  if (robot.error || !robot.data) {
    const notFound =
      robot.error instanceof ApiError &&
      (robot.error.status === 404 || robot.error.status === 422)
    return (
      <div className="space-y-4 p-6">
        {backLink}
        <AlertNotification
          level="error"
          message={
            notFound
              ? "This robot is not registered in the workspace."
              : `Error loading robot: ${robot.error?.message ?? "unknown error"}`
          }
        />
      </div>
    )
  }

  const data = robot.data
  const safetyState = caseFieldText(latestCase.data?.fields, "safety_state")
  const profileMode = caseFieldText(latestCase.data?.fields, "profile_mode")

  return (
    <div className="size-full overflow-auto">
      <div className="container flex max-w-[1000px] flex-col space-y-10 py-8">
        <div className="space-y-3">
          {backLink}
          <h2 className="font-mono text-2xl font-semibold tracking-tight">
            {data.robot_id}
          </h2>
          <p className="text-base text-muted-foreground">
            Registered {new Date(data.created_at).toLocaleString()}
          </p>
        </div>

        <section aria-labelledby="robot-metadata" className="space-y-2">
          <h3 id="robot-metadata" className="text-sm font-medium">
            Metadata
          </h3>
          <dl className="divide-y rounded-md border px-4">
            <MetaRow label="Robot id">
              <span className="font-mono">{data.robot_id}</span>
            </MetaRow>
            <MetaRow label="Site">{data.site ?? "—"}</MetaRow>
            <MetaRow label="Model">{data.model ?? "—"}</MetaRow>
            <MetaRow label="Morphology">{data.morphology ?? "—"}</MetaRow>
            <MetaRow label="Finding signatures">
              {data.require_finding_signature ? "Required" : "Optional"}
            </MetaRow>
            <MetaRow label="Safety state (latest finding)">
              <SafetyStateValue
                hasFindings={latest !== null}
                loading={
                  findings.isLoading ||
                  (latest !== null && latestCase.isLoading)
                }
                canReadCases={canReadCases}
                safetyState={safetyState}
                profileMode={profileMode}
              />
            </MetaRow>
          </dl>
        </section>

        <section aria-labelledby="robot-keys" className="space-y-3">
          <div className="flex items-center justify-between gap-2">
            <h3 id="robot-keys" className="text-sm font-medium">
              Keys
            </h3>
            {canUpdate ? (
              <Button
                variant="outline"
                size="sm"
                className="h-7"
                onClick={() => setAddKeyOpen(true)}
              >
                <PlusIcon className="mr-1 size-3.5" />
                Add key
              </Button>
            ) : null}
          </div>
          {keys.isLoading ? <Skeleton className="h-24 w-full" /> : null}
          {keys.error ? (
            <AlertNotification
              level="error"
              message={`Error loading keys: ${keys.error.message}`}
            />
          ) : null}
          {keys.data ? (
            <RobotKeysTable
              workspaceId={workspaceId}
              keys={keys.data.items}
              canUpdate={canUpdate}
            />
          ) : null}
        </section>

        <section aria-labelledby="robot-findings" className="space-y-3">
          <h3 id="robot-findings" className="text-sm font-medium">
            Findings
          </h3>
          <FindingsTimeline
            workspaceId={workspaceId}
            canReadCases={canReadCases}
            loading={findings.isLoading}
            error={findings.error}
            items={findings.data?.items ?? []}
            truncated={findings.data?.truncated ?? false}
          />
        </section>
      </div>

      <AddRobotKeyDialog
        workspaceId={workspaceId}
        open={addKeyOpen}
        onOpenChange={setAddKeyOpen}
        robodrRobotId={data.robot_id}
      />
    </div>
  )
}

function SafetyStateValue({
  hasFindings,
  loading,
  canReadCases,
  safetyState,
  profileMode,
}: {
  hasFindings: boolean
  loading: boolean
  canReadCases: boolean
  safetyState: string | null
  profileMode: string | null
}) {
  if (!canReadCases) {
    return (
      <span className="text-muted-foreground">Needs case:read permission</span>
    )
  }
  if (loading) {
    return <Skeleton className="h-4 w-40" />
  }
  if (!hasFindings || !safetyState) {
    return <span className="text-muted-foreground">Not reported</span>
  }
  return (
    <span className="font-mono text-xs">
      {safetyState}
      {profileMode ? (
        <span className="text-muted-foreground"> (mode {profileMode})</span>
      ) : null}
    </span>
  )
}

/** Props for {@link FindingsTimeline}. */
export interface FindingsTimelineProps {
  workspaceId: string
  canReadCases: boolean
  loading: boolean
  error: Error | null
  items: readonly CaseReadMinimal[]
  truncated: boolean
}

/** Timeline of a robot's RoboDR cases, newest activity first. */
export function FindingsTimeline({
  workspaceId,
  canReadCases,
  loading,
  error,
  items,
  truncated,
}: FindingsTimelineProps) {
  if (!canReadCases) {
    return (
      <p className="text-xs text-muted-foreground">
        Viewing findings needs the case:read permission.
      </p>
    )
  }
  if (loading) {
    return <Skeleton className="h-24 w-full" />
  }
  if (error) {
    return (
      <AlertNotification
        level="error"
        message={`Error loading findings: ${error.message}`}
      />
    )
  }
  if (items.length === 0) {
    return (
      <Empty className="border border-dashed">
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <RadarIcon className="size-5 text-muted-foreground/60" />
          </EmptyMedia>
          <EmptyTitle>No findings yet</EmptyTitle>
          <EmptyDescription>
            Cases appear here when this robot reports a RoboDR finding.
          </EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }
  return (
    <div className="space-y-2">
      <ol className="relative space-y-0 border-l pl-4" aria-label="Findings">
        {items.map((item) => {
          const robodr = parseRobodrPayload(item.payload)
          const seen = formatEpochMs(robodr?.lastSeenMs ?? null)
          return (
            <li key={item.id} className="relative py-2">
              <span
                className="absolute -left-[21px] top-3.5 size-2 rounded-full bg-muted-foreground/50"
                aria-hidden
              />
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <span className="text-muted-foreground tabular-nums">
                  {seen ?? new Date(item.updated_at).toLocaleString()}
                </span>
                <CaseBadge {...SEVERITIES[item.severity]} />
                <CaseBadge {...STATUSES[item.status]} />
                {robodr?.occurrenceCount ? (
                  <span className="text-muted-foreground">
                    {robodr.occurrenceCount}×
                  </span>
                ) : null}
              </div>
              <Link
                href={`/workspaces/${workspaceId}/cases/${item.id}`}
                className="mt-1 block text-sm underline-offset-2 hover:underline"
              >
                <span className="mr-2 font-mono text-xs text-muted-foreground">
                  {item.short_id}
                </span>
                {item.summary}
              </Link>
              {robodr?.ruleId ? (
                <p className="font-mono text-xs text-muted-foreground">
                  {robodr.ruleId}
                </p>
              ) : null}
            </li>
          )
        })}
      </ol>
      {truncated ? (
        <p className="text-xs text-muted-foreground">
          Showing the most recently updated findings. Use the cases list to see
          all of them.
        </p>
      ) : null}
    </div>
  )
}
