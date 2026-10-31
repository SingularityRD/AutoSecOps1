"use client"

import { type ComponentProps, memo } from "react"
import type { Streamdown } from "streamdown"
import { MarkdownWithFrontmatter } from "@/components/ai-elements/markdown-with-frontmatter"
import { getStreamdownRehypePlugins } from "@/lib/sanitize-markdown"
import { cn } from "@/lib/utils"

type ResponseProps = ComponentProps<typeof Streamdown>

const responseRehypePlugins = getStreamdownRehypePlugins()

export const Response = memo(
  ({ className, children, ...props }: ResponseProps) => (
    <MarkdownWithFrontmatter
      {...props}
      className={cn(
        "size-full [&>*:first-child]:mt-0 [&>*:last-child]:mb-0",
        className
      )}
      enableFrontmatter={false}
      rehypePlugins={responseRehypePlugins}
    >
      {children}
    </MarkdownWithFrontmatter>
  ),
  (prevProps, nextProps) => prevProps.children === nextProps.children
)

Response.displayName = "Response"
