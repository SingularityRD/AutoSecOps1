import { env } from "@/env.mjs"
import type { SiteConfig } from "@/types"

export const siteConfig: SiteConfig = {
  name: "AutoSecOps",
  author: "AutoSecOps",
  description:
    "The AI-native security automation platform for security teams and agents.",
  keywords: ["Next.js", "React", "Tailwind CSS", "Radix UI", "shadcn/ui"],
  url: {
    base: env.NEXT_PUBLIC_APP_URL,
    author: "AutoSecOps",
  },
  links: {
    docs: "https://docs.singularityrd.com",
    support: "mailto:info@singularityrd.com?subject=AutoSecOps%20support",
    sales: "mailto:info@singularityrd.com?subject=AutoSecOps%20sales",
  },
  ogImage: `${env.NEXT_PUBLIC_APP_URL}/og.jpg`,
}

export const routeConfig = {
  home: "/workspaces",
}
