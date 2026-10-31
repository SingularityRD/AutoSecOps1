import { expect, test } from "@playwright/test"
import type { SecretRead, SecretReadMinimal } from "@/client"

import {
  apiJson,
  apiText,
  cleanup,
  firstWorkspaceId,
  uniqueToken,
} from "./utils/api"

test.describe("credentials", () => {
  test("analyst creates a key-value credential without exposing its value", async ({
    page,
  }) => {
    const workspaceId = await firstWorkspaceId(page.request)
    const token = uniqueToken()
    const name = `smoke_credential_${token}`
    const key = "API_TOKEN"
    // Synthetic value; the test checks it never comes back from the API.
    const value = `synthetic-value-${token}`
    const secretsPath = `/api/workspaces/${workspaceId}/secrets`

    try {
      await page.goto(`/workspaces/${workspaceId}/credentials`)
      // The header button; an empty inventory can render a second one.
      await page
        .getByRole("button", { name: "Create credential", exact: true })
        .first()
        .click()

      const dialog = page.getByRole("dialog", { name: "Create credential" })
      await expect(dialog).toBeVisible()
      await dialog.getByPlaceholder("Name (snake case)").fill(name)
      await dialog
        .getByPlaceholder("Description", { exact: true })
        .fill("Frontend smoke test")
      await dialog.getByPlaceholder("Key", { exact: true }).first().fill(key)
      await dialog
        .getByPlaceholder("Value", { exact: true })
        .first()
        .fill(value)

      const created = page.waitForResponse(
        (response) =>
          response.request().method() === "POST" &&
          new URL(response.url()).pathname === secretsPath
      )
      await dialog
        .getByRole("button", { name: "Create credential", exact: true })
        .click()
      const createdResponse = await created
      expect(createdResponse.status()).toBe(201)
      const createdText = await createdResponse.text()
      await expect(dialog).toBeHidden()

      await expect(page.getByText(name, { exact: true }).first()).toBeVisible()

      const listResponse = await page.request.get(secretsPath)
      const listText = await listResponse.text()
      expect(listResponse.ok()).toBe(true)
      const secret = (JSON.parse(listText) as SecretReadMinimal[]).find(
        (item) => item.name === name
      )
      expect(secret, "Created credential should be listed").toBeTruthy()
      if (!secret) {
        return
      }
      expect(secret.keys).toEqual([key])

      // Read the credential back through every endpoint that returns it,
      // including the detail endpoints whose schema carries key values.
      const searchParams = new URLSearchParams({
        environment: secret.environment,
        name,
        id: secret.id,
      })
      const detailResponses = {
        create: createdText,
        list: listText,
        detailByName: await apiText(
          page.request.get(`${secretsPath}/${encodeURIComponent(name)}`)
        ),
        searchByNameAndId: await apiText(
          page.request.get(`${secretsPath}/search?${searchParams}`)
        ),
      }
      const detail = JSON.parse(detailResponses.detailByName) as SecretRead
      expect(detail.id).toBe(secret.id)
      const searched = JSON.parse(
        detailResponses.searchByNameAndId
      ) as SecretRead[]
      expect(searched.map((item) => item.id)).toEqual([secret.id])

      for (const [endpoint, body] of Object.entries(detailResponses)) {
        expect(
          body,
          `Secret value must never be returned by the ${endpoint} response`
        ).not.toContain(value)
      }
    } finally {
      const secrets = await apiJson<SecretReadMinimal[]>(
        page.request.get(secretsPath)
      ).catch(() => [] as SecretReadMinimal[])
      for (const secret of secrets.filter((item) => item.name === name)) {
        await cleanup(
          "delete smoke credential",
          page.request.delete(`${secretsPath}/${secret.id}`)
        )
      }
    }
  })
})
