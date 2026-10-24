"use client"

import { PlatformLicenseStatus } from "@/components/admin/platform-license-status"

export default function AdminLicensePage() {
  return (
    <div className="size-full overflow-auto">
      <div className="container flex h-full max-w-[1000px] flex-col space-y-12">
        <div className="flex w-full">
          <div className="items-start space-y-3 text-left">
            <h2 className="text-2xl font-semibold tracking-tight">License</h2>
            <p className="text-base text-muted-foreground">
              Status of the license key that unlocks paid features on this
              deployment.
            </p>
          </div>
        </div>

        <PlatformLicenseStatus />
      </div>
    </div>
  )
}
