"use client"

import { useParams } from "next/navigation"
import { RobotDetail } from "@/components/robot-edr/robot-detail"

export default function WorkspaceRobotDetailPage() {
  const params = useParams<{ robotId: string }>()
  const robotId = params?.robotId ?? ""
  return <RobotDetail robotId={robotId} />
}
