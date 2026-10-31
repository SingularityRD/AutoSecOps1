import { expect, test } from "@playwright/test"
import type { LicenseRead } from "@/client"

import { apiJson } from "./utils/api"
import {
  SUPERUSER_EMAIL,
  SUPERUSER_PASSWORD,
  signInWithBasicAuth,
} from "./utils/auth"

// The license page is for platform admins, so sign in as the superuser.
test.use({ storageState: { cookies: [], origins: [] } })

test.describe("license status", () => {
  test("platform admin sees the license status and deployment ID", async ({
    page,
  }) => {
    await signInWithBasicAuth(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD)
    const license = await apiJson<LicenseRead>(
      page.request.get("/api/admin/license")
    )

    await page.goto("/admin/license")
    await expect(
      page.getByRole("heading", { name: "License", exact: true })
    ).toBeVisible()
    await expect(page.getByText("Status", { exact: true })).toBeVisible()
    await expect(
      page.getByRole("heading", { name: "Deployment ID" })
    ).toBeVisible()
    await expect(
      page.getByText(license.deployment_id, { exact: true }).first()
    ).toBeVisible()
    await expect(page.getByText("Failed to load license status")).toHaveCount(0)

    // CI runs without a license key, so the unlicensed state must explain
    // how to get one instead of failing silently.
    if (license.status === "missing") {
      await expect(page.getByText("No license key installed")).toBeVisible()
      await expect(page.getByText("No license", { exact: true })).toBeVisible()
    }
  })
})
