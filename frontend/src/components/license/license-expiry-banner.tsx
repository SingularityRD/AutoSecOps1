"use client"

import { AlertTriangleIcon, XIcon } from "lucide-react"
import { useEffect, useState } from "react"
import type { LicenseNoticeLevel, LicenseNoticeRead } from "@/client"
import { Button } from "@/components/ui/button"
import { useLicenseNotice } from "@/hooks/use-license-notice"
import { cn } from "@/lib/utils"

/** Vendor contact shown when a license needs renewal or replacement. */
export const LICENSE_CONTACT = "info@singularityrd.com"

const DISMISS_KEY_PREFIX = "autosecops:license-notice-dismissed"

function dismissKey(notice: LicenseNoticeRead): string {
  // A new level or expiry date shows the banner again in the same session.
  return `${DISMISS_KEY_PREFIX}:${notice.level}:${notice.expires_at ?? ""}`
}

function readDismissed(key: string): boolean {
  try {
    return window.sessionStorage.getItem(key) === "1"
  } catch {
    return false
  }
}

function writeDismissed(key: string): void {
  try {
    window.sessionStorage.setItem(key, "1")
  } catch {
    // Storage can be unavailable (private mode); dismissal then lasts until reload.
  }
}

function formatDate(value: string | null | undefined): string {
  if (!value) {
    return "-"
  }
  return new Date(value).toLocaleDateString()
}

/**
 * Build the banner message for a license notice.
 */
export function licenseNoticeMessage(notice: LicenseNoticeRead): string {
  const level: LicenseNoticeLevel | null | undefined = notice.level
  switch (level) {
    case "expiring": {
      const days = notice.days_remaining ?? 0
      const dayLabel = days === 1 ? "day" : "days"
      return `Your AutoSecOps license expires in ${days} ${dayLabel}, on ${formatDate(notice.expires_at)}. Contact ${LICENSE_CONTACT} to renew.`
    }
    case "grace":
      return `Your AutoSecOps license expired. Paid features stay on until ${formatDate(notice.grace_ends_at)}. Contact ${LICENSE_CONTACT} to renew.`
    case "expired":
      return `Your AutoSecOps license and its grace period expired, and paid features are off. Contact ${LICENSE_CONTACT} to renew.`
    case "invalid":
      return `The installed AutoSecOps license key is invalid, and paid features are off. Ask a platform admin to check the license page, or contact ${LICENSE_CONTACT}.`
    default:
      return ""
  }
}

/**
 * Banner that warns organization administrators about license expiry.
 *
 * Shows when the license expires within 30 days, is in its grace period, or
 * is expired or invalid. Unlicensed Community installs never see it. Each
 * notice can be dismissed for the rest of the browser session.
 */
export function LicenseExpiryBanner() {
  const { notice } = useLicenseNotice()
  const [dismissed, setDismissed] = useState(true)
  const key = notice?.level ? dismissKey(notice) : null

  useEffect(() => {
    setDismissed(key === null || readDismissed(key))
  }, [key])

  if (!notice?.level || key === null || dismissed) {
    return null
  }

  const severe = notice.level === "expired" || notice.level === "invalid"

  function handleDismiss() {
    if (key !== null) {
      writeDismissed(key)
    }
    setDismissed(true)
  }

  return (
    <div
      role="status"
      className={cn(
        "flex items-center gap-2 border-b px-4 py-2 text-sm",
        severe
          ? "border-destructive/50 bg-destructive/5 text-destructive dark:text-red-300"
          : "border-amber-400 bg-amber-50 text-amber-700 dark:bg-amber-950/40 dark:text-amber-300"
      )}
    >
      <AlertTriangleIcon className="size-4 shrink-0" />
      <span className="flex-1">{licenseNoticeMessage(notice)}</span>
      <Button
        type="button"
        variant="ghost"
        size="icon"
        className="size-6 shrink-0"
        aria-label="Dismiss license notice"
        onClick={handleDismiss}
      >
        <XIcon className="size-4" />
      </Button>
    </div>
  )
}
