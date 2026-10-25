import type { AxiosAdapter, InternalAxiosRequestConfig } from "axios"
import { OpenAPI } from "@/client"
import { client, getBaseUrl } from "@/lib/api"
import * as utils from "@/lib/utils"

const LEGACY_FALLBACK = "http://localhost:8000"

function setRuntimeEnv(value: Record<string, unknown> | undefined) {
  // Cast through unknown: next-runtime-env types `__ENV` as ProcessEnv.
  const win = window as unknown as { __ENV?: Record<string, unknown> }
  if (value === undefined) {
    delete win.__ENV
  } else {
    win.__ENV = value
  }
}

/** Sends a request through the legacy client and returns its resolved URL. */
async function resolveClientUrl(path: string): Promise<string> {
  let captured: InternalAxiosRequestConfig | undefined
  const adapter: AxiosAdapter = async (config) => {
    captured = config
    return { data: null, status: 200, statusText: "OK", headers: {}, config }
  }
  await client.get(path, { adapter })
  if (!captured) {
    throw new Error("Request was not dispatched")
  }
  return client.getUri(captured)
}

describe("getBaseUrl", () => {
  afterEach(() => {
    setRuntimeEnv(undefined)
    jest.restoreAllMocks()
  })

  it("uses NEXT_PUBLIC_API_URL from the runtime env when it is set", () => {
    setRuntimeEnv({ NEXT_PUBLIC_API_URL: "https://app.example.test/api" })

    expect(getBaseUrl()).toBe("https://app.example.test/api")
    expect(OpenAPI.BASE).toBe("https://app.example.test/api")
  })

  it("falls back to same-origin /api before the runtime env is injected", () => {
    setRuntimeEnv(undefined)

    expect(getBaseUrl()).toBe(`${window.location.origin}/api`)
    expect(getBaseUrl()).not.toBe(LEGACY_FALLBACK)
    expect(OpenAPI.BASE).not.toBe(LEGACY_FALLBACK)
  })

  it("falls back to same-origin /api when the runtime value is empty", () => {
    setRuntimeEnv({ NEXT_PUBLIC_API_URL: "  " })

    expect(getBaseUrl()).toBe(`${window.location.origin}/api`)
  })

  it("picks up a runtime env that is injected after module import", async () => {
    setRuntimeEnv(undefined)
    expect(OpenAPI.BASE).toBe(`${window.location.origin}/api`)
    expect(await resolveClientUrl("/info")).toBe(
      `${window.location.origin}/api/info`
    )

    setRuntimeEnv({ NEXT_PUBLIC_API_URL: "https://app.example.test/api" })

    expect(OpenAPI.BASE).toBe("https://app.example.test/api")
    expect(await resolveClientUrl("/info")).toBe(
      "https://app.example.test/api/info"
    )
  })

  it("never sends browser requests to the legacy localhost:8000 fallback", async () => {
    setRuntimeEnv(undefined)

    const url = await resolveClientUrl("/info")

    expect(new URL(url).origin).toBe(window.location.origin)
    expect(url.startsWith(LEGACY_FALLBACK)).toBe(false)
  })

  it("keeps the server-side resolution order", () => {
    jest.spyOn(utils, "isServer").mockReturnValue(true)
    const originalServer = process.env.NEXT_SERVER_API_URL
    const originalPublic = process.env.NEXT_PUBLIC_API_URL
    try {
      process.env.NEXT_SERVER_API_URL = "http://internal.example.test:8000"
      process.env.NEXT_PUBLIC_API_URL = "https://app.example.test/api"
      expect(getBaseUrl()).toBe("http://internal.example.test:8000")

      delete process.env.NEXT_SERVER_API_URL
      expect(getBaseUrl()).toBe("https://app.example.test/api")

      delete process.env.NEXT_PUBLIC_API_URL
      expect(getBaseUrl()).toBe("http://api:8000")
    } finally {
      if (originalServer === undefined) {
        delete process.env.NEXT_SERVER_API_URL
      } else {
        process.env.NEXT_SERVER_API_URL = originalServer
      }
      if (originalPublic === undefined) {
        delete process.env.NEXT_PUBLIC_API_URL
      } else {
        process.env.NEXT_PUBLIC_API_URL = originalPublic
      }
    }
  })
})
