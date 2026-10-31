"use client"

import { useSearchParams } from "next/navigation"
import { Suspense } from "react"
import { VerifyEmail } from "@/components/auth/verify-email"
import { CenteredSpinner } from "@/components/loading/spinner"

function VerifyEmailContent() {
  const searchParams = useSearchParams()
  return <VerifyEmail token={searchParams?.get("token") ?? null} />
}

export default function Page() {
  return (
    <Suspense fallback={<CenteredSpinner />}>
      <VerifyEmailContent />
    </Suspense>
  )
}
