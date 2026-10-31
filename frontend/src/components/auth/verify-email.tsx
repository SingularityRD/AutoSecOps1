"use client"

import Image from "next/image"
import Link from "next/link"
import AutoSecOpsIcon from "public/icon.png"
import { useState } from "react"
import { authVerifyVerify } from "@/client"
import { Icons } from "@/components/icons"
import { Button } from "@/components/ui/button"
import {
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  getVerifyEmailFailure,
  type VerifyEmailFailure,
} from "@/lib/email-verification"

type VerifyState =
  | { kind: "ready" }
  | { kind: "verifying" }
  | { kind: "verified" }
  | { kind: "failed"; reason: VerifyEmailFailure | "unknown" }

interface VerifyEmailProps {
  /** The token from the emailed link, or null when the link has none. */
  token: string | null
}

function describe(state: VerifyState): { title: string; body: string } {
  switch (state.kind) {
    case "ready":
    case "verifying":
      return {
        title: "Verify your email",
        body: "Confirm that this email address belongs to you. Only continue if you created an AutoSecOps account.",
      }
    case "verified":
      return {
        title: "Email verified",
        body: "Your email is verified. You can now sign in.",
      }
    case "failed":
      switch (state.reason) {
        case "already_verified":
          return {
            title: "Already verified",
            body: "This email is already verified. You can sign in.",
          }
        case "invalid":
          return {
            title: "Link invalid or expired",
            body: "This verification link is invalid, expired, or was already used. Sign in to request a new one.",
          }
        case "rate_limited":
          return {
            title: "Too many attempts",
            body: "Wait a minute and try again.",
          }
        case "unknown":
          return {
            title: "Verification failed",
            body: "Something went wrong. Try again later.",
          }
      }
  }
}

/**
 * Confirms an email address from the emailed verification link.
 *
 * The token is submitted only when the user clicks: mail scanners that open
 * links must not verify an account on the user's behalf.
 */
export function VerifyEmail({ token }: VerifyEmailProps) {
  const [state, setState] = useState<VerifyState>(
    token ? { kind: "ready" } : { kind: "failed", reason: "invalid" }
  )

  async function verify() {
    if (!token) {
      return
    }
    setState({ kind: "verifying" })
    try {
      await authVerifyVerify({ requestBody: { token } })
      setState({ kind: "verified" })
    } catch (error) {
      const reason = getVerifyEmailFailure(error)
      if (reason === null) {
        console.error("Error verifying email", error)
      }
      setState({ kind: "failed", reason: reason ?? "unknown" })
    }
  }

  const { title, body } = describe(state)
  const canVerify = state.kind === "ready" || state.kind === "verifying"

  return (
    <div className="container flex size-full items-center justify-center">
      <div className="flex w-full flex-1 flex-col justify-center gap-2 px-8 sm:max-w-md">
        <CardHeader className="items-center space-y-2 text-center">
          <Image
            src={AutoSecOpsIcon}
            alt="AutoSecOps"
            className="mb-8 size-16"
          />
          <CardTitle className="text-2xl">{title}</CardTitle>
          <CardDescription>{body}</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-2">
          {canVerify ? (
            <Button
              className="w-full text-sm"
              disabled={state.kind === "verifying"}
              onClick={verify}
              type="button"
            >
              {state.kind === "verifying" && (
                <Icons.spinner className="mr-2 size-4 animate-spin" />
              )}
              Verify email
            </Button>
          ) : (
            <Button asChild className="w-full text-sm">
              <Link href="/sign-in">Go to sign in</Link>
            </Button>
          )}
        </CardContent>
      </div>
    </div>
  )
}
