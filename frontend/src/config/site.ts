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
    github: "https://github.com/SingularityRD/AutoSecOps1",
    docs: "https://github.com/SingularityRD/AutoSecOps1/tree/main/docs",
    playbooks: "https://github.com/SingularityRD/AutoSecOps1",
  },
  ogImage: `${env.NEXT_PUBLIC_APP_URL}/og.jpg`,
}

export const routeConfig = {
  home: "/workspaces",
}
