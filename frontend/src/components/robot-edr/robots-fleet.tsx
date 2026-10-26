"use client"

import { PlusIcon, RadarIcon, SearchIcon } from "lucide-react"
import Link from "next/link"
import { useSearchParams } from "next/navigation"
import { useId, useMemo, useState } from "react"
import type { RobotKeyRead, RobotRead } from "@/client"
import { useScopeCheck } from "@/components/auth/scope-guard"
import { CaseBadge } from "@/components/cases/case-badge"
import { SEVERITIES } from "@/components/cases/case-categories"
import { CenteredSpinner } from "@/components/loading/spinner"
import { AlertNotification } from "@/components/notifications"
import {
  ROBOT_EDR_ENTITLEMENT,
  ROBOT_READ_SCOPE,
  ROBOT_UPDATE_SCOPE,
  RobotEdrAccessGate,
} from "@/components/robot-edr/robot-edr-access"
import {
  AddRobotKeyDialog,
  RegisterRobotDialog,
} from "@/components/robot-edr/robot-edr-dialogs"
import {
  KeyStatusBadge,
  RobotKeysTable,
} from "@/components/robot-edr/robot-keys-table"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { useEntitlements } from "@/hooks/use-entitlements"
import {
  useRobodrFleetCases,
  useRobotKeys,
  useRobots,
} from "@/hooks/use-robot-edr"
import {
  formatEpochMs,
  type RobotFindingStats,
  type RobotKeySummary,
  summarizeRobotFindings,
  summarizeRobotKeys,
} from "@/lib/robodr"
import { useWorkspaceId } from "@/providers/workspace-id"

/** Fleet filter on findings and key state. */
export type FleetStatusFilter = "all" | "open-findings" | "no-active-key"

const ALL_SITES = "__all__"

/** One row of the fleet table. */
export interface FleetRow {
  robot: RobotRead
  stats: RobotFindingStats
  keySummary: RobotKeySummary
}

const EMPTY_STATS: RobotFindingStats = {
  lastSeenMs: null,
  openCases: 0,
  highestOpenSeverity: null,
}

/**
 * Applies the fleet filters: free text over robot id, model and morphology,
 * an exact site, and a findings or key-state filter.
 */
export function filterFleetRows(
  rows: readonly FleetRow[],
  {
    query,
    site,
    status,
  }: { query: string; site: string | null; status: FleetStatusFilter }
): FleetRow[] {
  const needle = query.trim().toLowerCase()
  return rows.filter(({ robot, stats, keySummary }) => {
    if (site !== null && robot.site !== site) return false
    if (status === "open-findings" && stats.openCases === 0) return false
    if (status === "no-active-key" && keySummary === "active") return false
    if (!needle) return true
    return [robot.robot_id, robot.model, robot.morphology, robot.site].some(
      (value) => value?.toLowerCase().includes(needle)
    )
  })
}

/** Header action that opens the register robot dialog. */
export function RegisterRobotButton() {
  const workspaceId = useWorkspaceId()
  const canUpdate = useScopeCheck(ROBOT_UPDATE_SCOPE)
  const { hasEntitlement } = useEntitlements({ enabled: canUpdate === true })
  const [open, setOpen] = useState(false)
  if (canUpdate !== true || !hasEntitlement(ROBOT_EDR_ENTITLEMENT)) {
    return null
  }
  return (
    <>
      <Button
        variant="outline"
        size="sm"
        className="h-7 bg-background"
        onClick={() => setOpen(true)}
      >
        <PlusIcon className="mr-1 size-3.5" />
        Register robot
      </Button>
      <RegisterRobotDialog
        workspaceId={workspaceId}
        open={open}
        onOpenChange={setOpen}
      />
    </>
  )
}

function KeySummaryCell({ summary }: { summary: RobotKeySummary }) {
  if (summary === "active") {
    return <KeyStatusBadge status="active" />
  }
  return (
    <span className="text-xs text-muted-foreground">
      {summary === "none" ? "No keys" : "No active key"}
    </span>
  )
}

/** The Robots (fleet) page, behind the Robot EDR access gate. */
export function RobotsFleet() {
  return (
    <RobotEdrAccessGate>
      <RobotsFleetContent />
    </RobotEdrAccessGate>
  )
}

function RobotsFleetContent() {
  const workspaceId = useWorkspaceId()
  const searchParams = useSearchParams()
  const filterId = useId()
  const canRead = useScopeCheck(ROBOT_READ_SCOPE) === true
  const canUpdate = useScopeCheck(ROBOT_UPDATE_SCOPE) === true
  const canReadCases = useScopeCheck("case:read") === true
  const robots = useRobots(workspaceId, { enabled: canRead })
  const keys = useRobotKeys(workspaceId, { enabled: canRead })
  const cases = useRobodrFleetCases(workspaceId, { enabled: canReadCases })
  const [query, setQuery] = useState(() => searchParams?.get("q") ?? "")
  const [site, setSite] = useState<string>(ALL_SITES)
  const [status, setStatus] = useState<FleetStatusFilter>("all")
  const [registerOpen, setRegisterOpen] = useState(false)
  const [addRelayOpen, setAddRelayOpen] = useState(false)

  const allKeys = keys.data?.items
  const rows = useMemo<FleetRow[]>(() => {
    const stats = summarizeRobotFindings(cases.data?.items ?? [])
    const keysByRobot = new Map<string, RobotKeyRead[]>()
    for (const key of allKeys ?? []) {
      if (!key.robot_id) continue
      keysByRobot.set(key.robot_id, [
        ...(keysByRobot.get(key.robot_id) ?? []),
        key,
      ])
    }
    return (robots.data?.items ?? []).map((robot) => ({
      robot,
      stats: stats.get(robot.robot_id) ?? EMPTY_STATS,
      keySummary: summarizeRobotKeys(keysByRobot.get(robot.robot_id) ?? []),
    }))
  }, [robots.data, allKeys, cases.data])

  const relayKeys = useMemo(
    () => (allKeys ?? []).filter((key) => key.role === "relay"),
    [allKeys]
  )
  const sites = useMemo(
    () =>
      Array.from(
        new Set(
          (robots.data?.items ?? [])
            .map((robot) => robot.site)
            .filter((value): value is string => Boolean(value))
        )
      ).sort(),
    [robots.data]
  )
  const visibleRows = filterFleetRows(rows, {
    query,
    site: site === ALL_SITES ? null : site,
    status,
  })

  if (robots.isLoading) {
    return <CenteredSpinner />
  }
  if (robots.error) {
    return (
      <div className="p-6">
        <AlertNotification
          level="error"
          message={`Error loading robots: ${robots.error.message}`}
        />
      </div>
    )
  }

  return (
    <div className="size-full overflow-auto">
      <div className="container flex max-w-[1200px] flex-col space-y-8 py-8">
        <div className="space-y-3">
          <h2 className="text-2xl font-semibold tracking-tight">Robots</h2>
          <p className="text-base text-muted-foreground">
            Robots that report RoboDR findings to this workspace, with their
            keys and open cases.
          </p>
        </div>

        {rows.length === 0 ? (
          <Empty className="border border-dashed">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <RadarIcon className="size-5 text-muted-foreground/60" />
              </EmptyMedia>
              <EmptyTitle>No robots registered</EmptyTitle>
              <EmptyDescription>
                Register a robot and its public keys before robodr-uplink can
                send findings.
              </EmptyDescription>
            </EmptyHeader>
            {canUpdate ? (
              <Button size="sm" onClick={() => setRegisterOpen(true)}>
                <PlusIcon className="mr-1 size-3.5" />
                Register robot
              </Button>
            ) : null}
          </Empty>
        ) : (
          <section aria-labelledby={`${filterId}-fleet`} className="space-y-3">
            <h3 id={`${filterId}-fleet`} className="sr-only">
              Fleet
            </h3>
            <div className="flex flex-wrap items-end gap-2">
              <div className="relative w-full max-w-xs">
                <Label htmlFor={`${filterId}-query`} className="sr-only">
                  Search robots
                </Label>
                <SearchIcon
                  className="pointer-events-none absolute left-2 top-2 size-4 text-muted-foreground"
                  aria-hidden
                />
                <Input
                  id={`${filterId}-query`}
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search robot id, model, site"
                  className="h-8 pl-8 text-xs"
                />
              </div>
              <div>
                <Label htmlFor={`${filterId}-site`} className="sr-only">
                  Site
                </Label>
                <Select value={site} onValueChange={setSite}>
                  <SelectTrigger
                    id={`${filterId}-site`}
                    className="h-8 w-44 text-xs"
                    aria-label="Filter by site"
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={ALL_SITES}>All sites</SelectItem>
                    {sites.map((value) => (
                      <SelectItem key={value} value={value}>
                        {value}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label htmlFor={`${filterId}-status`} className="sr-only">
                  Status
                </Label>
                <Select
                  value={status}
                  onValueChange={(value) =>
                    setStatus(value as FleetStatusFilter)
                  }
                >
                  <SelectTrigger
                    id={`${filterId}-status`}
                    className="h-8 w-48 text-xs"
                    aria-label="Filter by status"
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All robots</SelectItem>
                    <SelectItem value="open-findings">
                      With open findings
                    </SelectItem>
                    <SelectItem value="no-active-key">No active key</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {cases.error ? (
              <AlertNotification
                level="warning"
                message={`Finding statistics are unavailable: ${cases.error.message}`}
              />
            ) : null}
            {!canReadCases ? (
              <p className="text-xs text-muted-foreground">
                Finding statistics need the case:read permission.
              </p>
            ) : null}
            {cases.data?.truncated || robots.data?.truncated ? (
              <p className="text-xs text-muted-foreground">
                Statistics cover the most recently updated findings only.
              </p>
            ) : null}

            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Robot</TableHead>
                    <TableHead>Site</TableHead>
                    <TableHead>Model</TableHead>
                    <TableHead>Morphology</TableHead>
                    <TableHead>Last seen</TableHead>
                    <TableHead className="text-right">Open cases</TableHead>
                    <TableHead>Highest open severity</TableHead>
                    <TableHead>Keys</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {visibleRows.length === 0 ? (
                    <TableRow>
                      <TableCell
                        colSpan={8}
                        className="py-6 text-center text-xs text-muted-foreground"
                      >
                        No robots match these filters.
                      </TableCell>
                    </TableRow>
                  ) : (
                    visibleRows.map(({ robot, stats, keySummary }) => (
                      <TableRow key={robot.id}>
                        <TableCell className="font-mono text-xs">
                          <Link
                            href={`/workspaces/${workspaceId}/robots/${robot.id}`}
                            className="underline-offset-2 hover:underline"
                          >
                            {robot.robot_id}
                          </Link>
                        </TableCell>
                        <TableCell className="text-xs">
                          {robot.site ?? "—"}
                        </TableCell>
                        <TableCell className="text-xs">
                          {robot.model ?? "—"}
                        </TableCell>
                        <TableCell className="text-xs">
                          {robot.morphology ?? "—"}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {cases.isLoading
                            ? "…"
                            : (formatEpochMs(stats.lastSeenMs) ?? "Never")}
                        </TableCell>
                        <TableCell className="text-right text-xs tabular-nums">
                          {cases.isLoading ? "…" : stats.openCases}
                        </TableCell>
                        <TableCell>
                          {stats.highestOpenSeverity ? (
                            <CaseBadge
                              {...SEVERITIES[stats.highestOpenSeverity]}
                            />
                          ) : (
                            <span className="text-xs text-muted-foreground">
                              —
                            </span>
                          )}
                        </TableCell>
                        <TableCell>
                          <KeySummaryCell summary={keySummary} />
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
          </section>
        )}

        <section aria-labelledby={`${filterId}-relay`} className="space-y-3">
          <div className="flex items-center justify-between gap-2">
            <div className="space-y-1">
              <h3
                id={`${filterId}-relay`}
                className="flex items-center gap-2 text-sm font-medium"
              >
                Relay keys
                <Badge variant="secondary">{relayKeys.length}</Badge>
              </h3>
              <p className="text-xs text-muted-foreground">
                Workspace-wide keys that sign batches for any registered robot.
              </p>
            </div>
            {canUpdate ? (
              <Button
                variant="outline"
                size="sm"
                className="h-7"
                onClick={() => setAddRelayOpen(true)}
              >
                <PlusIcon className="mr-1 size-3.5" />
                Add relay key
              </Button>
            ) : null}
          </div>
          {keys.error ? (
            <AlertNotification
              level="error"
              message={`Error loading keys: ${keys.error.message}`}
            />
          ) : (
            <RobotKeysTable
              workspaceId={workspaceId}
              keys={relayKeys}
              canUpdate={canUpdate}
            />
          )}
        </section>
      </div>

      <RegisterRobotDialog
        workspaceId={workspaceId}
        open={registerOpen}
        onOpenChange={setRegisterOpen}
      />
      <AddRobotKeyDialog
        workspaceId={workspaceId}
        open={addRelayOpen}
        onOpenChange={setAddRelayOpen}
      />
    </div>
  )
}
