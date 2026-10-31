"use client"

import { useState } from "react"
import { ApiError, authVerifyRequestToken } from "@/client"
import { Icons } from "@/components/icons"
import { Button } from "@/components/ui/button"

type ResendState = "idle" | "sending" | "sent" | "rate_limited" | "failed"

interface CheckInboxProps {
  /** The address the verification email goes to. */
  email: string
  /** Optional action to leave this state, such as returning to sign in. */
  onBack?: () => void
}

/**
 * Tells an unverified user to open the emailed link, and lets them ask for a
 * new one. The API answers the same whether or not a send was queued, so the
 * confirmation never reveals whether the account exists.
 */
export function CheckInbox({ email, onBack }: CheckInboxProps) {
  const [state, setState] = useState<ResendState>("idle")

  async function resend() {
    setState("sending")
    try {
      await authVerifyRequestToken({ requestBody: { email } })
      setState("sent")
    } catch (error) {
      if (error instanceof ApiError && error.status === 429) {
        setState("rate_limited")
      } else {
        console.error("Error requesting verification email", error)
        setState("failed")
      }
    }
  }

  return (
    <div className="grid gap-4 text-sm" data-testid="check-inbox">
      <p className="text-muted-foreground">
        Verify your email to finish setting up your account. We sent a link to{" "}
        <span className="font-medium text-foreground">{email}</span>. The link
        works once and expires after a short time.
      </p>
      <p className="text-muted-foreground">
        No email? Check your spam folder, or ask an administrator to verify your
        account if this deployment cannot send email.
      </p>
      {state === "sent" && (
        <output className="block">
          If your account still needs verification, a new email is on its way.
        </output>
      )}
      {state === "rate_limited" && (
        <p role="alert" className="text-destructive">
          Too many requests. Wait a few minutes and try again.
        </p>
      )}
      {state === "failed" && (
        <p role="alert" className="text-destructive">
          Could not request a new email. Try again later.
        </p>
      )}
      <Button
        className="w-full text-sm"
        variant="outline"
        disabled={state === "sending"}
        onClick={resend}
        type="button"
      >
        {state === "sending" && (
          <Icons.spinner className="mr-2 size-4 animate-spin" />
        )}
        Resend verification email
      </Button>
      {onBack && (
        <Button
          className="w-full text-sm"
          variant="ghost"
          onClick={onBack}
          type="button"
        >
          Back to sign in
        </Button>
      )}
    </div>
  )
}
