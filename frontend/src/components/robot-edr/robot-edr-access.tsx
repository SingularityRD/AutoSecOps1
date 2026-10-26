"use client"

import { ArrowUpRight, ShieldOffIcon } from "lucide-react"
import type { ReactNode } from "react"
import { useScopeCheck } from "@/components/auth/scope-guard"
import { EntitlementRequiredEmptyState } from "@/components/entitlement-required-empty-state"
import { CenteredSpinner } from "@/components/loading/spinner"
import { Button } from "@/components/ui/button"
import { useEntitlements } from "@/hooks/use-entitlements"

/** Entitlement that gates every Robot EDR surface. */
export const ROBOT_EDR_ENTITLEMENT = "robot_edr"

/** Scope needed to view robots and keys. */
export const ROBOT_READ_SCOPE = "robot:read"

/** Scope needed to register robots and keys or revoke keys. */
export const ROBOT_UPDATE_SCOPE = "robot:update"

/**
 * Renders its children only when the user holds `robot:read` and the
 * organization has the `robot_edr` entitlement; otherwise renders the
 * loading, permission-missing, entitlement-missing or entitlement-unknown
 * state. Entitlements are not requested without `robot:read`.
 */
export function RobotEdrAccessGate({ children }: { children: ReactNode }) {
  const canRead = useScopeCheck(ROBOT_READ_SCOPE)
  const {
    hasEntitlement,
    hasEntitlementData,
    isLoading: entitlementsLoading,
  } = useEntitlements({ enabled: canRead === true })

  if (canRead === undefined) {
    return <CenteredSpinner />
  }
  if (canRead === false) {
    return (
      <div className="flex h-full p-6">
        <EntitlementRequiredEmptyState
          title="You don't have access to robots"
          description="Viewing robots needs the robot:read permission. Ask a workspace admin for access."
          icon={<ShieldOffIcon className="size-6" />}
        />
      </div>
    )
  }
  if (entitlementsLoading) {
    return <CenteredSpinner />
  }
  if (!hasEntitlementData) {
    return (
      <div className="flex h-full p-6">
        <EntitlementRequiredEmptyState
          title="Unable to check plan access"
          description="Reload the page to try again."
        >
          <Button
            variant="outline"
            size="sm"
            onClick={() => window.location.reload()}
          >
            Reload
          </Button>
        </EntitlementRequiredEmptyState>
      </div>
    )
  }
  if (!hasEntitlement(ROBOT_EDR_ENTITLEMENT)) {
    return (
      <div className="flex h-full p-6">
        <EntitlementRequiredEmptyState
          title="Upgrade required"
          description="Robot EDR is unavailable on your current plan. Install a license that grants the robot_edr entitlement."
        >
          <Button
            variant="link"
            asChild
            className="text-muted-foreground"
            size="sm"
          >
            <a href="mailto:sales@singularityrd.com">
              Contact sales <ArrowUpRight className="size-4" />
            </a>
          </Button>
        </EntitlementRequiredEmptyState>
      </div>
    )
  }
  return <>{children}</>
}
