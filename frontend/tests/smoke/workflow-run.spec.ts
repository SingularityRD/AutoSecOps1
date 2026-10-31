import { expect, test } from "@playwright/test"
import type {
  WorkflowCommitResponse,
  WorkflowExecutionCreateResponse,
  WorkflowReadMinimal,
} from "@/client"

import { apiJson, cleanup, firstWorkspaceId, uniqueToken } from "./utils/api"

type ExecutionStatus = { status: string }

/** A one-action workflow that runs without credentials or network access. */
function workflowDefinition(title: string): string {
  return [
    "definition:",
    `  title: ${title}`,
    "  description: Synthetic frontend smoke workflow",
    "  entrypoint:",
    "    ref: reshape",
    "  actions:",
    "    - ref: reshape",
    "      action: core.transform.reshape",
    "      args:",
    "        value:",
    "          smoke: ok",
    "",
  ].join("\n")
}

test.describe("workflow lifecycle", () => {
  test.describe.configure({ timeout: 180_000 })

  test("analyst imports, publishes, and runs a workflow", async ({ page }) => {
    const workspaceId = await firstWorkspaceId(page.request)
    const title = `Smoke workflow ${uniqueToken()}`
    let workflowId: string | undefined

    try {
      // Create: import a definition through the workflows page.
      await page.goto(`/workspaces/${workspaceId}/workflows`)
      await page.getByRole("button", { name: "Create", exact: true }).click()
      await page
        .getByRole("menuitem")
        .filter({ hasText: "Import a workflow file" })
        .click()

      const importDialog = page.getByRole("dialog", {
        name: "Import workflow from file",
      })
      await expect(importDialog).toBeVisible()
      await importDialog.locator('input[type="file"]').setInputFiles({
        name: "smoke-workflow.yml",
        mimeType: "application/yaml",
        buffer: Buffer.from(workflowDefinition(title)),
      })
      const created = page.waitForResponse(
        (response) =>
          response.request().method() === "POST" &&
          new URL(response.url()).pathname.endsWith(
            `/workspaces/${workspaceId}/workflows`
          )
      )
      await importDialog.getByRole("button", { name: "Upload" }).click()
      const createdResponse = await created
      expect(createdResponse.status()).toBe(201)
      workflowId = ((await createdResponse.json()) as WorkflowReadMinimal).id

      await page.waitForURL(
        new RegExp(`/workspaces/[^/]+/workflows/${workflowId}$`)
      )
      await expect(page.getByText("Workflow trigger")).toBeVisible()

      // Save: publishing commits the draft as a new version.
      const committed = page.waitForResponse(
        (response) =>
          response.request().method() === "POST" &&
          new URL(response.url()).pathname.endsWith(
            `/workflows/${workflowId}/commit`
          )
      )
      await page.getByRole("button", { name: "Publish", exact: true }).click()
      const commitResponse = await committed
      expect(commitResponse.ok()).toBe(true)
      const commit = (await commitResponse.json()) as WorkflowCommitResponse
      expect(commit.status, JSON.stringify(commit.errors ?? [])).toBe("success")

      const workflow = await apiJson<{ version?: number | null }>(
        page.request.get(
          `/api/workspaces/${workspaceId}/workflows/${workflowId}`
        )
      )
      expect(workflow.version).toBeGreaterThanOrEqual(1)

      // Run: start the draft from the builder and wait for it to finish.
      const started = page.waitForResponse(
        (response) =>
          response.request().method() === "POST" &&
          new URL(response.url()).pathname.endsWith(
            "/workflow-executions/draft"
          )
      )
      await page.getByRole("button", { name: "Run", exact: true }).click()
      const startedResponse = await started
      expect(startedResponse.ok()).toBe(true)
      const execution =
        (await startedResponse.json()) as WorkflowExecutionCreateResponse
      expect(execution.wf_exec_id).toBeTruthy()

      const executionPath = `/api/workspaces/${workspaceId}/workflow-executions/${encodeURIComponent(
        execution.wf_exec_id
      )}/compact`
      await expect
        .poll(
          async () => {
            const response = await page.request.get(executionPath)
            if (!response.ok()) {
              return `HTTP ${response.status()}`
            }
            return ((await response.json()) as ExecutionStatus).status
          },
          {
            message: "Draft execution should complete",
            timeout: 120_000,
            intervals: [1_000, 2_000, 5_000],
          }
        )
        .toBe("COMPLETED")
    } finally {
      if (workflowId) {
        await cleanup(
          "delete smoke workflow",
          page.request.delete(
            `/api/workspaces/${workspaceId}/workflows/${workflowId}`
          )
        )
      }
    }
  })
})
