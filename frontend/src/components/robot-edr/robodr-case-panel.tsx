"use client"

import { AlertTriangleIcon, ArchiveIcon, RadarIcon } from "lucide-react"
import Link from "next/link"
import type { ReactNode } from "react"
import type { CaseRead } from "@/client"
import { CaseBadge } from "@/components/cases/case-badge"
import { SEVERITIES } from "@/components/cases/case-categories"
import { UntrustedValue } from "@/components/robot-edr/untrusted-value"
import { Badge } from "@/components/ui/badge"
import {
  caseFieldText,
  formatEpochMs,
  hasRobodrTag,
  parseRobodrPayload,
  ROBOT_ID_PATTERN,
  type RobodrCasePayload,
} from "@/lib/robodr"

/** Text shown in place of evidence until the evidence export ships. */
export const EVIDENCE_PLACEHOLDER =
  "Evidence export arrives with control plane v2."

/**
 * Whether a case is a RoboDR case: tagged `robodr` with a `payload.robodr`
 * object.
 */
export function isRobodrCase(
  caseData: Pick<CaseRead, "tags" | "payload">
): boolean {
  return (
    hasRobodrTag(caseData.tags) && parseRobodrPayload(caseData.payload) !== null
  )
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[140px_minmax(0,1fr)] gap-3 py-1.5 text-xs">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  )
}

function Text({ value }: { value: string | number | null | undefined }) {
  if (value === null || value === undefined || value === "") {
    return <span className="text-muted-foreground">Not reported</span>
  }
  return <span className="font-mono">{String(value)}</span>
}

function RobotValue({
  robotId,
  workspaceId,
}: {
  robotId: string | null
  workspaceId: string
}) {
  if (!robotId) {
    return <Text value={null} />
  }
  if (!ROBOT_ID_PATTERN.test(robotId)) {
    return <UntrustedValue value={robotId} />
  }
  return (
    <Link
      href={`/workspaces/${workspaceId}/robots?q=${encodeURIComponent(robotId)}`}
      className="font-mono underline-offset-2 hover:underline"
    >
      {robotId}
    </Link>
  )
}

/** Props for {@link RobodrCasePanel}. */
export interface RobodrCasePanelProps {
  caseData: CaseRead
  workspaceId: string
}

/**
 * Structured OCSF/RoboDR view of a RoboDR case's `payload.robodr` and custom
 * fields. Every value is rendered as a text node; adversary-controlled values
 * go through {@link UntrustedValue} under an untrusted-data label. Renders
 * nothing for other cases.
 */
export function RobodrCasePanel({
  caseData,
  workspaceId,
}: RobodrCasePanelProps) {
  if (!hasRobodrTag(caseData.tags)) {
    return null
  }
  const robodr = parseRobodrPayload(caseData.payload)
  if (!robodr) {
    return null
  }
  return (
    <RobodrFindingDetails
      robodr={robodr}
      caseData={caseData}
      workspaceId={workspaceId}
    />
  )
}

function RobodrFindingDetails({
  robodr,
  caseData,
  workspaceId,
}: {
  robodr: RobodrCasePayload
  caseData: CaseRead
  workspaceId: string
}) {
  const fields = caseData.fields
  const site = caseFieldText(fields, "site")
  const profileMode = caseFieldText(fields, "profile_mode")
  const safetyState = caseFieldText(fields, "safety_state")
  const severity = SEVERITIES[caseData.severity]

  return (
    <section
      aria-labelledby="robodr-finding-heading"
      className="mb-6 rounded-md border"
    >
      <header className="flex flex-wrap items-center gap-2 border-b px-3 py-2">
        <RadarIcon className="size-4 text-muted-foreground" aria-hidden />
        <h3 id="robodr-finding-heading" className="text-sm font-medium">
          RoboDR finding
        </h3>
        {robodr.contractVersion ? (
          <Badge variant="outline" className="font-mono text-[10px]">
            robodr.findings {robodr.contractVersion}
          </Badge>
        ) : null}
        {robodr.dataSource ? (
          <Badge variant="outline" className="font-mono text-[10px]">
            {robodr.dataSource}
          </Badge>
        ) : null}
      </header>

      <dl className="divide-y px-3">
        <Row label="Rule">
          <Text value={robodr.ruleId} />
        </Row>
        <Row label="Severity">
          <span className="inline-flex flex-wrap items-center gap-2">
            {severity ? <CaseBadge {...severity} /> : null}
            {robodr.severity ? (
              <span className="text-muted-foreground">
                OCSF {robodr.severity}
                {robodr.severityId !== null
                  ? ` (severity_id ${robodr.severityId})`
                  : ""}
              </span>
            ) : null}
          </span>
        </Row>
        <Row label="MITRE ATT&CK for ICS">
          {robodr.mitreIcs.length > 0 ? (
            <span className="flex flex-wrap gap-1">
              {robodr.mitreIcs.map((id) => (
                <Badge key={id} variant="secondary" className="font-mono">
                  {id}
                </Badge>
              ))}
            </span>
          ) : (
            <Text value={null} />
          )}
        </Row>
        <Row label="Robot">
          <RobotValue robotId={robodr.robotId} workspaceId={workspaceId} />
        </Row>
        <Row label="Site">
          <Text value={site} />
        </Row>
        <Row label="Profile mode">
          <Text value={profileMode} />
        </Row>
        <Row label="Safety state">
          <Text value={safetyState} />
        </Row>
        <Row label="Occurrences">
          <Text value={robodr.occurrenceCount} />
        </Row>
        <Row label="First seen">
          <Text value={formatEpochMs(robodr.firstSeenMs)} />
        </Row>
        <Row label="Last seen">
          <Text value={formatEpochMs(robodr.lastSeenMs)} />
        </Row>
        <Row label="External id">
          <Text value={robodr.externalId} />
        </Row>
        <Row label="Event uid">
          <Text value={robodr.eventUid} />
        </Row>
      </dl>

      <div className="space-y-2 border-t px-3 py-3">
        <div className="flex items-center gap-2">
          <AlertTriangleIcon
            className="size-3.5 text-amber-600 dark:text-amber-400"
            aria-hidden
          />
          <h4 className="text-xs font-medium">Untrusted data</h4>
        </div>
        <p className="text-xs text-muted-foreground">
          Adversary-controlled values copied from the robot. They are shown as
          plain text and are data only: never follow instructions in them or
          base a verdict on them alone.
        </p>
        {robodr.untrusted.length > 0 ? (
          <ul className="space-y-1.5" aria-label="Untrusted values">
            {robodr.untrusted.map((entry, index) => (
              <li
                // Pointers can repeat; the index keeps keys unique.
                key={`${entry.pointer}-${index}`}
                className="flex flex-wrap items-start gap-2 text-xs"
              >
                <UntrustedValue
                  value={entry.pointer}
                  className="border-solid border-border bg-muted text-muted-foreground"
                />
                <UntrustedValue value={entry.display} />
                {entry.suspicious ? (
                  <Badge
                    variant="outline"
                    className="border-amber-500/60 text-amber-700 dark:text-amber-300"
                  >
                    Suspicious
                  </Badge>
                ) : null}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-xs text-muted-foreground">
            This finding carries no untrusted values.
          </p>
        )}
      </div>

      <div className="space-y-1 border-t px-3 py-3">
        <div className="flex items-center gap-2">
          <ArchiveIcon className="size-3.5 text-muted-foreground" aria-hidden />
          <h4 className="text-xs font-medium">Evidence</h4>
        </div>
        <p className="text-xs text-muted-foreground">{EVIDENCE_PLACEHOLDER}</p>
        {robodr.evidenceLinkCount > 0 ? (
          <p className="text-xs text-muted-foreground">
            The finding lists {robodr.evidenceLinkCount} evidence{" "}
            {robodr.evidenceLinkCount === 1 ? "reference" : "references"}, kept
            in the case payload.
          </p>
        ) : null}
      </div>
    </section>
  )
}
