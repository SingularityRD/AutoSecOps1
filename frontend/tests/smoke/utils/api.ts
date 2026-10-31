import { randomUUID } from "node:crypto"
import {
  type APIRequestContext,
  type APIResponse,
  expect,
} from "@playwright/test"
import type { WorkspacesListWorkspacesResponse } from "@/client"

/**
 * Await an API response, assert it succeeded, and return its JSON body.
 */
export async function apiJson<T>(response: Promise<APIResponse>): Promise<T> {
  const result = await response
  await expect(result, await describeResponse(result)).toBeOK()
  return (await result.json()) as T
}

/**
 * Await an API response, assert it succeeded, and return its raw body text.
 */
export async function apiText(response: Promise<APIResponse>): Promise<string> {
  const result = await response
  await expect(result, await describeResponse(result)).toBeOK()
  return await result.text()
}

/**
 * Return the ID of the first workspace the signed-in user can open.
 */
export async function firstWorkspaceId(
  request: APIRequestContext
): Promise<string> {
  const workspaces = await apiJson<WorkspacesListWorkspacesResponse>(
    request.get("/api/workspaces")
  )
  expect(workspaces.length, "Expected a seeded workspace").toBeGreaterThan(0)
  return workspaces[0].id
}

/**
 * Build a short, collision-free token for names of resources a test creates.
 */
export function uniqueToken(): string {
  return randomUUID().replaceAll("-", "").slice(0, 12)
}

/**
 * Best-effort cleanup that never masks the test's own failure.
 */
export async function cleanup(
  description: string,
  response: Promise<APIResponse>
): Promise<void> {
  try {
    const result = await response
    if (!result.ok() && result.status() !== 404) {
      console.warn(`Cleanup failed (${description}): ${result.status()}`)
    }
  } catch (error) {
    console.warn(`Cleanup failed (${description}):`, error)
  }
}

async function describeResponse(response: APIResponse): Promise<string> {
  const text = await response.text().catch(() => "")
  return `${response.url()} -> ${response.status()} ${text.slice(0, 500)}`
}
