import {
  ENTITLEMENT_MINIMUM_PLAN,
  planFeatureTitle,
  planLabel,
} from "@/lib/plans"

describe("plan labels", () => {
  test("name the smallest plan that unlocks an entitlement", () => {
    expect(planLabel("case_addons")).toBe("Team plan")
    expect(planLabel("semantic_search")).toBe("Business plan")
    expect(planLabel("tunnels")).toBe("Enterprise plan")
    expect(planFeatureTitle("agent_channels")).toBe("Business plan feature")
  })

  test("never label a Team or Business entitlement as Enterprise", () => {
    const enterpriseOnly = Object.entries(ENTITLEMENT_MINIMUM_PLAN)
      .filter(([, plan]) => plan === "Enterprise")
      .map(([entitlement]) => entitlement)
      .sort()
    expect(enterpriseOnly).toEqual(["robot_edr", "tunnels"])
  })
})
