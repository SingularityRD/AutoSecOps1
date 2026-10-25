import axios from "axios"
import { OpenAPI } from "@/client"

import { isServer } from "@/lib/utils"

/** Path the default Caddy reverse proxy serves the API under. */
const SAME_ORIGIN_API_PATH = "/api"

/**
 * Reads `NEXT_PUBLIC_API_URL` from the runtime env that `PublicEnvScript`
 * injects into `window.__ENV`. Returns `undefined` until the script has run.
 */
function getRuntimePublicApiUrl(): string | undefined {
  const runtimeEnv = (window as Window & { __ENV?: Record<string, unknown> })
    .__ENV
  const value = runtimeEnv?.NEXT_PUBLIC_API_URL
  if (typeof value === "string" && value.trim() !== "") {
    return value
  }
  return undefined
}

/**
 * Resolves the API base URL for the current execution environment. Call it
 * per request rather than caching the result, because the browser runtime env
 * may not be populated yet when modules are first evaluated.
 *
 * Server side:
 * 1. NEXT_SERVER_API_URL (process.env)
 * 2. NEXT_PUBLIC_API_URL (process.env)
 * 3. http://api:8000
 *
 * Client side:
 * 1. NEXT_PUBLIC_API_URL (runtime env injected into `window.__ENV`)
 * 2. Same-origin `/api`, which is where the reverse proxy serves the API
 *
 * @returns The absolute base URL for API requests
 */
export function getBaseUrl(): string {
  // Server side
  if (isServer()) {
    return (
      process.env.NEXT_SERVER_API_URL ??
      process.env.NEXT_PUBLIC_API_URL ??
      "http://api:8000"
    )
  }

  // Client side
  return (
    getRuntimePublicApiUrl() ??
    `${window.location.origin}${SAME_ORIGIN_API_PATH}`
  )
}

// Legacy axiosclient
export const client = axios.create({
  withCredentials: true,
})

// Resolve the base URL per request so a request made before the runtime env
// is injected does not pin a stale URL for the lifetime of the page.
client.interceptors.request.use((config) => {
  config.baseURL ??= getBaseUrl()
  return config
})

export type Client = typeof client

Object.defineProperty(OpenAPI, "BASE", {
  configurable: true,
  enumerable: true,
  get: getBaseUrl,
})
OpenAPI.WITH_CREDENTIALS = true
