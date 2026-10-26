"use client"

import {
  AlertTriangleIcon,
  ArchiveIcon,
  DownloadIcon,
  RadarIcon,
  ShieldCheckIcon,
} from "lucide-react"
import Link from "next/link"
import type { ReactNode } from "react"
import {
  type ApiError,
  type CaseAttachmentRead,
  type CaseRead,
  caseAttachmentsDownloadAttachment,
  caseAttachmentsListAttachments,
} from "@/client"
import { CaseBadge } from "@/components/cases/case-badge"
import { SEVERITIES } from "@/components/cases/case-categories"
import { UntrustedValue } from "@/components/robot-edr/untrusted-value"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { toast } from "@/components/ui/use-toast"
import { useQuery } from "@/lib/query"
import {
  caseFieldText,
  formatEpochMs,
  hasRobodrTag,
  parseRobodrPayload,
  ROBOT_ID_PATTERN,
  type RobodrCasePayload,
} from "@/lib/robodr"

/** Text shown when no verified evidence is stored for the case. */
export const EVIDENCE_NONE =
  "No verified evidence is stored for this case. Run the Robot evidence export workflow to export and verify the finding's black-box records."

/**
 * Verified evidence reports among a case's attachments, newest first.
 *
 * Trusts only the server-side `robodr_evidence` mark, which the API sets on
 * the report it writes after an export passed robodr.control-plane §11.6 and
 * never carries to a copy. The `robodr-evidence-` file name proves nothing.
 */
export function verifiedEvidenceReports(
  attachments: CaseAttachmentRead[] | undefined
): CaseAttachmentRead[] {
  return (attachments ?? []).filter(
    (attachment) =>
      attachment.robodr_evidence === true &&
      !attachment.is_deleted &&
      attachment.content_type === "text/plain"
  )
}

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

function formatBytes(size: number): string {
  if (size < 1024) {
    return `${size} B`
  }
  return `${(size / 1024).toFixed(1)} KiB`
}

/**
 * The case's verified evidence reports. Reads the case attachments (shared
 * cache with the Attachments panel) and shows only reports the API marked as
 * verified evidence; it never derives evidence from the finding's own links.
 */
export function RobodrEvidence({
  caseId,
  workspaceId,
  evidenceLinkCount,
}: {
  caseId: string
  workspaceId: string
  evidenceLinkCount: number
}) {
  const { data, isLoading, error } = useQuery<CaseAttachmentRead[], ApiError>({
    queryKey: ["case-attachments", caseId, workspaceId],
    queryFn: async () =>
      await caseAttachmentsListAttachments({ caseId, workspaceId }),
    meta: { suppressErrorToast: true },
  })
  const reports = verifiedEvidenceReports(data)

  const download = async (attachment: CaseAttachmentRead) => {
    try {
      const response = await caseAttachmentsDownloadAttachment({
        caseId,
        workspaceId,
        attachmentId: attachment.id,
      })
      if (!response.download_url) {
        throw new Error("No download URL received from server")
      }
      const link = document.createElement("a")
      link.href = response.download_url
      link.download = attachment.file_name
      link.rel = "noopener"
      link.style.display = "none"
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
    } catch {
      toast({
        title: "Download failed",
        description: `Failed to download ${attachment.file_name}`,
      })
    }
  }

  return (
    <div className="space-y-2">
      {isLoading ? (
        <p className="text-xs text-muted-foreground">Loading evidence...</p>
      ) : error ? (
        <p className="text-xs text-muted-foreground">
          The case attachments could not be read, so verified evidence is not
          shown.
        </p>
      ) : reports.length > 0 ? (
        <ul className="space-y-1.5" aria-label="Verified evidence">
          {reports.map((report) => (
            <li
              key={report.id}
              className="flex flex-wrap items-center gap-2 text-xs"
            >
              <Badge
                variant="outline"
                className="gap-1 border-emerald-500/60 text-emerald-700 dark:text-emerald-300"
              >
                <ShieldCheckIcon className="size-3" aria-hidden />
                Verified
              </Badge>
              <span className="font-mono">{report.file_name}</span>
              <span className="text-muted-foreground">
                {formatBytes(report.size)} report,{" "}
                {new Date(report.created_at).toLocaleString()}
              </span>
              <Button
                variant="ghost"
                size="sm"
                className="h-6 px-2 text-xs"
                onClick={() => void download(report)}
                aria-label={`Download ${report.file_name}`}
              >
                <DownloadIcon className="size-3" aria-hidden />
              </Button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-xs text-muted-foreground">{EVIDENCE_NONE}</p>
      )}
      {reports.length > 0 ? (
        <p className="text-xs text-muted-foreground">
          Each report names the signed black-box bundle the platform stored
          after checking the robot&apos;s signatures and hashes.
        </p>
      ) : null}
      {evidenceLinkCount > 0 ? (
        <p className="text-xs text-muted-foreground">
          The finding lists {evidenceLinkCount} evidence{" "}
          {evidenceLinkCount === 1 ? "reference" : "references"}, kept in the
          case payload.
        </p>
      ) : null}
    </div>
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
        <RobodrEvidence
          caseId={caseData.id}
          workspaceId={workspaceId}
          evidenceLinkCount={robodr.evidenceLinkCount}
        />
      </div>
    </section>
  )
}
