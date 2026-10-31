import { expect, test } from "@playwright/test"
import type { InvitationRead, RoleList } from "@/client"

import { apiJson, cleanup } from "./utils/api"
import { freshEmail } from "./utils/auth"

test.describe("organization members", () => {
  test("owner invites a member with an organization role", async ({
    page,
  }, testInfo) => {
    const email = freshEmail(testInfo.title)
    const roles = await apiJson<RoleList>(page.request.get("/api/rbac/roles"))
    // Prefer the least privileged preset organization role.
    const role =
      roles.items.find((item) => item.slug === "organization-member") ??
      roles.items.find((item) => item.slug === "organization-admin")
    expect(role, "Expected a preset organization role").toBeTruthy()
    if (!role) {
      return
    }
    let invitationId: string | undefined

    try {
      await page.goto("/organization/members")
      await expect(
        page.getByRole("heading", { name: "Members and access control" })
      ).toBeVisible()
      await page.getByRole("button", { name: "Invite member" }).click()

      const dialog = page.getByRole("dialog", { name: "Invite member" })
      await expect(dialog).toBeVisible()
      await dialog.getByPlaceholder("user@example.com").fill(email)
      await dialog.getByRole("combobox", { name: "Grant 1 role" }).click()
      await page.getByRole("option", { name: role.name, exact: true }).click()

      const created = page.waitForResponse(
        (response) =>
          response.request().method() === "POST" &&
          new URL(response.url()).pathname === "/api/invitations"
      )
      await dialog.getByRole("button", { name: "Send invitation" }).click()
      const createdResponse = await created
      expect(createdResponse.status()).toBe(201)
      const invitation = (await createdResponse.json()) as InvitationRead
      invitationId = invitation.id
      expect(invitation.email).toBe(email)

      // A SCIM advisory keeps the dialog open; otherwise it closes itself.
      if (await dialog.isVisible()) {
        await page.keyboard.press("Escape")
      }
      await expect(dialog).toBeHidden()
      await expect(page.getByText(email, { exact: true }).first()).toBeVisible()
    } finally {
      if (invitationId) {
        await cleanup(
          "revoke smoke invitation",
          page.request.delete(`/api/invitations/${invitationId}`)
        )
      }
    }
  })
})
