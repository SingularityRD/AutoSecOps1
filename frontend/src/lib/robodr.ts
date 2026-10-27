import type {
  CaseFieldRead,
  CaseReadMinimal,
  CaseSeverity,
  CaseStatus,
  CaseTagRead,
  RobotKeyRead,
} from "@/client"

/** Tag every case created from a RoboDR finding carries. */
export const ROBODR_CASE_TAG = "robodr"

/** Case statuses that count as open for fleet statistics. */
export const OPEN_CASE_STATUSES: readonly CaseStatus[] = [
  "new",
  "in_progress",
  "on_hold",
  "unknown",
  "other",
]

/** Longest untrusted value shown before it is cut. */
export const UNTRUSTED_DISPLAY_MAX = 512

/** Ed25519 public key as RoboDR prints it: 64 lower-case hex digits. */
export const PUBLIC_KEY_HEX_PATTERN = /^[0-9a-f]{64}$/

/** RoboDR robot ids as the finding contract allows them. */
export const ROBOT_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/

const SEVERITY_RANK: Record<CaseSeverity, number> = {
  other: 0,
  unknown: 0,
  informational: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
  fatal: 6,
}

/** One adversary-controlled value from `payload.robodr.untrusted.values`. */
export interface RobodrUntrustedValue {
  /** JSON pointer into the finding the value came from. */
  pointer: string
  /** Display text. Always rendered as inert plain text. */
  display: string
  /** The producer flagged the value as a likely injection attempt. */
  suspicious: boolean
}

/** The `payload.robodr` object of a RoboDR case, narrowed from `unknown`. */
export interface RobodrCasePayload {
  externalId: string | null
  findingId: string | null
  eventUid: string | null
  dataSource: string | null
  contractVersion: string | null
  robotId: string | null
  ruleId: string | null
  severity: string | null
  severityId: number | null
  occurrenceCount: number | null
  firstSeenMs: number | null
  lastSeenMs: number | null
  mitreIcs: string[]
  evidenceLinkCount: number
  untrustedLabel: string | null
  untrusted: RobodrUntrustedValue[]
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function asString(value: unknown): string | null {
  return typeof value === "string" ? value : null
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null
}

/**
 * Narrows a case payload to its `robodr` object.
 *
 * Returns `null` when the payload has no `robodr` object. Every member is
 * type-checked, so a malformed payload written by a workflow degrades to
 * missing values instead of a crash.
 */
export function parseRobodrPayload(payload: unknown): RobodrCasePayload | null {
  if (!isRecord(payload) || !isRecord(payload.robodr)) {
    return null
  }
  const robodr = payload.robodr
  const untrusted = isRecord(robodr.untrusted) ? robodr.untrusted : null
  const rawValues =
    untrusted && Array.isArray(untrusted.values) ? untrusted.values : []
  return {
    externalId: asString(robodr.external_id),
    findingId: asString(robodr.finding_id),
    eventUid: asString(robodr.event_uid),
    dataSource: asString(robodr.data_source),
    contractVersion: asString(robodr.contract_version),
    robotId: asString(robodr.robot_id),
    ruleId: asString(robodr.rule_id),
    severity: asString(robodr.severity),
    severityId: asNumber(robodr.severity_id),
    occurrenceCount: asNumber(robodr.occurrence_count),
    firstSeenMs: asNumber(robodr.first_seen_ms),
    lastSeenMs: asNumber(robodr.last_seen_ms),
    mitreIcs: Array.isArray(robodr.mitre_ics)
      ? robodr.mitre_ics.filter((id): id is string => typeof id === "string")
      : [],
    evidenceLinkCount: Array.isArray(robodr.evidence_links)
      ? robodr.evidence_links.length
      : 0,
    untrustedLabel: untrusted ? asString(untrusted.label) : null,
    untrusted: rawValues.filter(isRecord).map((entry) => ({
      pointer: asString(entry.pointer) ?? "",
      display:
        typeof entry.display === "string"
          ? entry.display
          : JSON.stringify(entry.display ?? null),
      suspicious: entry.suspicious === true,
    })),
  }
}

/** Whether a case carries the `robodr` tag. */
export function hasRobodrTag(
  tags: readonly CaseTagRead[] | undefined
): boolean {
  return (tags ?? []).some(
    (tag) => tag.ref === ROBODR_CASE_TAG || tag.name === ROBODR_CASE_TAG
  )
}

function isInvisibleOrControl(codePoint: number): boolean {
  return (
    codePoint < 0x20 ||
    (codePoint >= 0x7f && codePoint <= 0x9f) ||
    codePoint === 0xad ||
    codePoint === 0x061c ||
    (codePoint >= 0x200b && codePoint <= 0x200f) ||
    (codePoint >= 0x2028 && codePoint <= 0x202e) ||
    (codePoint >= 0x2060 && codePoint <= 0x206f) ||
    codePoint === 0xfeff ||
    (codePoint >= 0xfff9 && codePoint <= 0xfffb) ||
    (codePoint >= 0xe0000 && codePoint <= 0xe007f)
  )
}

/**
 * Makes an adversary-controlled string inert for display.
 *
 * Control, bidirectional, zero-width, line-separator and tag characters are
 * replaced by a visible `[U+XXXX]` marker, so the text cannot reorder, hide
 * or break the surrounding UI. The result is capped at
 * {@link UNTRUSTED_DISPLAY_MAX} characters. Callers must still render it as a
 * React text node, never as HTML or Markdown.
 */
export function neutralizeUntrustedText(
  value: string,
  max: number = UNTRUSTED_DISPLAY_MAX
): { text: string; truncated: boolean } {
  let text = ""
  let truncated = false
  for (const char of value) {
    const codePoint = char.codePointAt(0) ?? 0
    const piece = isInvisibleOrControl(codePoint)
      ? `[U+${codePoint.toString(16).toUpperCase().padStart(4, "0")}]`
      : char
    if (text.length + piece.length > max) {
      truncated = true
      break
    }
    text += piece
  }
  return { text, truncated }
}

/** Ranks a case severity; higher is worse. */
export function severityRank(severity: CaseSeverity): number {
  return SEVERITY_RANK[severity]
}

/** Returns the worse of two severities, treating `null` as none. */
export function maxSeverity(
  current: CaseSeverity | null,
  next: CaseSeverity
): CaseSeverity {
  if (current === null || severityRank(next) > severityRank(current)) {
    return next
  }
  return current
}

/** Whether a case status counts as open. */
export function isOpenStatus(status: CaseStatus): boolean {
  return OPEN_CASE_STATUSES.includes(status)
}

/** Per-robot statistics derived from the workspace's RoboDR cases. */
export interface RobotFindingStats {
  /** Latest `last_seen_ms` across the robot's findings. */
  lastSeenMs: number | null
  openCases: number
  highestOpenSeverity: CaseSeverity | null
}

/**
 * Groups RoboDR cases by `payload.robodr.robot_id` into fleet statistics.
 * Cases without the `robodr` tag or a robot id are skipped.
 */
export function summarizeRobotFindings(
  cases: readonly CaseReadMinimal[]
): Map<string, RobotFindingStats> {
  const stats = new Map<string, RobotFindingStats>()
  for (const item of cases) {
    if (!hasRobodrTag(item.tags)) continue
    const robodr = parseRobodrPayload(item.payload)
    if (!robodr?.robotId) continue
    const entry = stats.get(robodr.robotId) ?? {
      lastSeenMs: null,
      openCases: 0,
      highestOpenSeverity: null,
    }
    if (
      robodr.lastSeenMs !== null &&
      (entry.lastSeenMs === null || robodr.lastSeenMs > entry.lastSeenMs)
    ) {
      entry.lastSeenMs = robodr.lastSeenMs
    }
    if (isOpenStatus(item.status)) {
      entry.openCases += 1
      entry.highestOpenSeverity = maxSeverity(
        entry.highestOpenSeverity,
        item.severity
      )
    }
    stats.set(robodr.robotId, entry)
  }
  return stats
}

/** Status of a registered key at a point in time. */
export type RobotKeyStatus = "active" | "revoked" | "expired"

/** Works out whether a key can still authenticate. */
export function robotKeyStatus(
  key: Pick<RobotKeyRead, "revoked_at" | "expires_at">,
  now: number = Date.now()
): RobotKeyStatus {
  if (key.revoked_at) {
    return "revoked"
  }
  if (key.expires_at && new Date(key.expires_at).getTime() <= now) {
    return "expired"
  }
  return "active"
}

/** Summary of the keys bound to one robot. */
export type RobotKeySummary = "active" | "inactive" | "none"

/**
 * Summarizes a robot's bound keys: `active` when any can authenticate,
 * `inactive` when all are revoked or expired, `none` when it has no keys.
 */
export function summarizeRobotKeys(
  keys: readonly RobotKeyRead[],
  now: number = Date.now()
): RobotKeySummary {
  if (keys.length === 0) {
    return "none"
  }
  return keys.some((key) => robotKeyStatus(key, now) === "active")
    ? "active"
    : "inactive"
}

/** Reads a custom field value by its field id from a full case. */
export function caseFieldText(
  fields: readonly CaseFieldRead[] | undefined,
  id: string
): string | null {
  const field = (fields ?? []).find((candidate) => candidate.id === id)
  if (!field || field.value === null || field.value === undefined) {
    return null
  }
  return typeof field.value === "string"
    ? field.value
    : JSON.stringify(field.value)
}

/** Formats epoch milliseconds for display, or `null` when absent. */
export function formatEpochMs(ms: number | null): string | null {
  if (ms === null) {
    return null
  }
  const date = new Date(ms)
  return Number.isNaN(date.getTime()) ? null : date.toLocaleString()
}
