"use client"

import "@/styles/globals.scss"

import Cookies from "js-cookie"
import { useEffect } from "react"
import ErrorPage from "@/components/error"
import { fontSans } from "@/lib/fonts"
import { cn } from "@/lib/utils"
import { LAST_VIEWED_WORKSPACE_COOKIE } from "@/lib/workspace-cookie"

/**
 * Root error boundary. Next.js renders this in place of the root layout when
 * the layout itself (or one of its providers) throws, so it must render its
 * own `<html>` and `<body>` and must not depend on any layout provider such
 * as React Query, the theme provider, or the settings modal.
 */
export default function GlobalError({
  error,
}: {
  error: Error & { digest?: string }
}) {
  // Clear the last-viewed workspace so a reload does not revive the same
  // failing workspace. Read the cookie directly because the query client that
  // `useWorkspaceManager` needs is not mounted here.
  useEffect(() => {
    Cookies.remove(LAST_VIEWED_WORKSPACE_COOKIE)
  }, [])

  return (
    <html lang="en" className="h-full min-h-screen">
      <body
        className={cn(
          "flex h-screen min-h-screen items-center justify-center bg-background font-sans antialiased",
          fontSans.variable
        )}
      >
        <ErrorPage error={error} />
      </body>
    </html>
  )
}
