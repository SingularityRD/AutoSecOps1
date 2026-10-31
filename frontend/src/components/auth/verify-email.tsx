"use client"

import { zodResolver } from "@hookform/resolvers/zod"
import Image from "next/image"
import Link from "next/link"
import AutoSecOpsIcon from "public/icon.png"
import { useState } from "react"
import { useForm } from "react-hook-form"
import { z } from "zod"
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
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import {
  getVerifyEmailFailure,
  getVerifyEmailPasswordError,
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

const verifyEmailSchema = z
  .object({
    password: z
      .string()
      .min(12, "Password needs to be at least 12 characters long"),
    confirmPassword: z.string(),
  })
  .refine((values) => values.password === values.confirmPassword, {
    message: "Passwords do not match",
    path: ["confirmPassword"],
  })
type VerifyEmailForm = z.infer<typeof verifyEmailSchema>

function describe(state: VerifyState): { title: string; body: string } {
  switch (state.kind) {
    case "ready":
    case "verifying":
      return {
        title: "Verify your email",
        body: "Set the password for this account to confirm your email. You can reuse the password you signed up with. Any other sessions are signed out.",
      }
    case "verified":
      return {
        title: "Email verified",
        body: "Your email is verified. Sign in with the password you just set.",
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
 * Verification also sets the account password, so whoever proves the mailbox
 * owns the account even if someone else registered the address. The token is
 * submitted only with the form: mail scanners that open links must not
 * verify an account on the user's behalf.
 */
export function VerifyEmail({ token }: VerifyEmailProps) {
  const [state, setState] = useState<VerifyState>(
    token ? { kind: "ready" } : { kind: "failed", reason: "invalid" }
  )
  const form = useForm<VerifyEmailForm>({
    resolver: zodResolver(verifyEmailSchema),
    defaultValues: { password: "", confirmPassword: "" },
  })

  async function verify(values: VerifyEmailForm) {
    if (!token) {
      return
    }
    setState({ kind: "verifying" })
    try {
      await authVerifyVerify({
        requestBody: { token, password: values.password },
      })
      setState({ kind: "verified" })
    } catch (error) {
      const passwordError = getVerifyEmailPasswordError(error)
      if (passwordError !== null) {
        form.setError("password", { message: passwordError })
        setState({ kind: "ready" })
        return
      }
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
            <Form {...form}>
              <form onSubmit={form.handleSubmit(verify)} className="grid gap-4">
                <FormField
                  control={form.control}
                  name="password"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-xs">Password</FormLabel>
                      <FormControl>
                        <Input
                          type="password"
                          autoComplete="new-password"
                          {...field}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="confirmPassword"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-xs">
                        Confirm password
                      </FormLabel>
                      <FormControl>
                        <Input
                          type="password"
                          autoComplete="new-password"
                          {...field}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <Button
                  className="w-full text-sm"
                  disabled={state.kind === "verifying"}
                  type="submit"
                >
                  {state.kind === "verifying" && (
                    <Icons.spinner className="mr-2 size-4 animate-spin" />
                  )}
                  Verify email
                </Button>
              </form>
            </Form>
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
