import {
  type APIRequestContext,
  expect,
  type TestInfo,
  test,
} from "@playwright/test"

import { expectWorkspaceLanding, getWorkspaceId } from "./utils/auth"

type Entitlements = {
  git_sync: boolean
  case_addons: boolean
  workspace_chat: boolean
}

async function getEntitlements(
  pageRequest: APIRequestContext
): Promise<Entitlements> {
  const response = await pageRequest.get("/api/organization/entitlements")
  if (!response.ok()) {
    throw new Error(await response.text())
  }
  return (await response.json()) as Entitlements
}

async function skipIfEntitled(
  pageRequest: APIRequestContext,
  testInfo: TestInfo,
  entitlement: keyof Entitlements
) {
  const entitlements = await getEntitlements(pageRequest)
  if (!entitlements[entitlement]) {
    return
  }
  if (process.env.CI) {
    expect(
      entitlements[entitlement],
      "Run these tests against a base (no add-on) entitlement baseline"
    ).toBe(false)
  }
  testInfo.skip(true, `Requires ${entitlement} disabled`)
}

test.describe("entitlement gates", () => {
  test("locked sidebar item opens upgrade modal without navigation", async ({
    page,
  }, testInfo) => {
    await skipIfEntitled(page.request, testInfo, "workspace_chat")

    await page.goto("/workspaces")
    await expectWorkspaceLanding(page)

    await expect(async () => {
      await page.getByRole("button", { name: "Chat" }).click({
        timeout: 2_000,
      })
    }).toPass()

    await expect(
      page.getByRole("dialog", { name: "Upgrade to unlock this feature" })
    ).toBeVisible()
    await expect(page).not.toHaveURL(/\/chat(\/|$|\?)/)
  })

  // The inbox itself is open to every plan. Filtering it to one case's agent
  // runs (the `caseId` deep link from a case page) requires case add-ons, so
  // without them the page ignores the filter and shows the full inbox.
  test("inbox case filter deep link is ignored without case add-ons", async ({
    page,
  }, testInfo) => {
    await skipIfEntitled(page.request, testInfo, "case_addons")

    await page.goto("/workspaces")
    const workspaceId = await getWorkspaceId(page)

    await page.goto(
      `/workspaces/${workspaceId}/inbox?caseId=11111111-1111-4111-8111-111111111111`,
      { waitUntil: "domcontentloaded" }
    )

    await expect(page.getByPlaceholder("Search sessions...")).toBeVisible()
    await expect(page.getByText("Enterprise only")).toHaveCount(0)
    await expect(page.getByText("Filtered by case")).toHaveCount(0)
  })

  test("direct Git sync route renders the entitlement empty state", async ({
    page,
  }, testInfo) => {
    await skipIfEntitled(page.request, testInfo, "git_sync")

    await page.goto("/organization/vcs")

    await expect(page.getByRole("heading", { name: "Git sync" })).toBeVisible()
    await expect(page.getByText("Upgrade required")).toBeVisible()
    await expect(
      page.getByText("Git sync is unavailable on your current plan.")
    ).toBeVisible()
  })
})
