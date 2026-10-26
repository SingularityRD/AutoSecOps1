"use client"

import { Suspense } from "react"
import { CenteredSpinner } from "@/components/loading/spinner"
import { RobotsFleet } from "@/components/robot-edr/robots-fleet"

export default function WorkspaceRobotsPage() {
  return (
    <Suspense fallback={<CenteredSpinner />}>
      <RobotsFleet />
    </Suspense>
  )
}
