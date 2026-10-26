"use client"

import "@/lib/zod-config"

/**
 * Loads the global Zod configuration in the client bundle.
 *
 * The root layout is a server component, so it renders this component to make
 * sure `@/lib/zod-config` runs in the browser before any form validates.
 */
export function ZodConfigInit(): null {
  return null
}
