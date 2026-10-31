import type { Entitlement } from "@/client"

/** Commercial plan names shown in upgrade prompts. */
export type PlanName = "Community" | "Team" | "Business" | "Enterprise"

/**
 * Smallest plan that includes each entitlement.
 *
 * Mirrors `minimum_plan()` in `autosecops/licensing/plans.py`; the backend
 * unit test `tests/unit/test_plans_docs.py` fails if the two drift.
 */
export const ENTITLEMENT_MINIMUM_PLAN: Record<Entitlement, PlanName> = {
  custom_registry: "Community",
  workspace_chat: "Community",
  agent_addons: "Team",
  case_addons: "Team",
  forms: "Team",
  git_sync: "Team",
  service_accounts: "Team",
  agent_channels: "Business",
  external_secret_stores: "Business",
  multi_workspace: "Business",
  rbac_addons: "Business",
  semantic_search: "Business",
  watchtower: "Business",
  agent_runtime_preview: "Enterprise",
  robot_edr: "Enterprise",
  tunnels: "Enterprise",
}

/** Label such as "Team plan" for the smallest plan that unlocks `entitlement`. */
export function planLabel(entitlement: Entitlement): string {
  return `${ENTITLEMENT_MINIMUM_PLAN[entitlement]} plan`
}

/** Locked-feature title such as "Team plan feature". */
export function planFeatureTitle(entitlement: Entitlement): string {
  return `${planLabel(entitlement)} feature`
}
