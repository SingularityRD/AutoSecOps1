"use client"

import type { ComponentProps, ReactNode } from "react"
import { defaultRemarkPlugins } from "streamdown"
import { MarkdownWithFrontmatter } from "@/components/ai-elements/markdown-with-frontmatter"
import { isSafeFormLink, remarkFormMarkdown } from "@/lib/forms/markdown"
import {
  getStreamdownRehypePlugins,
  type MarkdownUrlPolicy,
} from "@/lib/sanitize-markdown"
import { cn } from "@/lib/utils"

type MarkdownProps = ComponentProps<typeof MarkdownWithFrontmatter>

/**
 * Anchor for form markdown. Renders a link only for `http(s)` and `mailto`
 * targets; anything else falls back to its plain text.
 */
export function FormMarkdownLink({
  href,
  children,
}: {
  href?: string
  children?: ReactNode
}) {
  if (!isSafeFormLink(href)) return <span>{children}</span>
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="font-medium text-primary underline underline-offset-2"
    >
      {children}
    </a>
  )
}

// A custom list replaces Streamdown's defaults, so keep GFM and math parsing
// and run the form filter after them.
const REMARK_PLUGINS = [
  ...Object.values(defaultRemarkPlugins),
  remarkFormMarkdown,
] as NonNullable<MarkdownProps["remarkPlugins"]>

const COMPONENTS = {
  a: FormMarkdownLink,
  img: () => null,
} as NonNullable<MarkdownProps["components"]>

/**
 * URL policy for form markdown. The link wildcard only hands `http(s)` and
 * `mailto` links on to `FormMarkdownLink`, which decides. No image URL is
 * allowed.
 */
export const FORM_MARKDOWN_URL_POLICY: MarkdownUrlPolicy = {
  allowedLinkPrefixes: ["*"],
  allowedImagePrefixes: [],
}

const REHYPE_PLUGINS = getStreamdownRehypePlugins(FORM_MARKDOWN_URL_POLICY)

/**
 * Markdown written by a form author: a description, a text block or a notice.
 *
 * Authors are trusted less than the people who read their forms, so this is
 * narrower than the chat `Response` component. Raw HTML is dropped from the
 * markdown tree before the renderer's raw-HTML parser can see it, images are
 * never rendered, and links work only for `http(s)` and `mailto`.
 */
export function FormMarkdown({
  children,
  className,
}: {
  children: string
  className?: string
}) {
  return (
    <MarkdownWithFrontmatter
      className={cn(
        "space-y-2 [&>*:first-child]:mt-0 [&>*:last-child]:mb-0",
        className
      )}
      parseIncompleteMarkdown={false}
      controls={false}
      remarkPlugins={REMARK_PLUGINS}
      components={COMPONENTS}
      rehypePlugins={REHYPE_PLUGINS}
    >
      {children}
    </MarkdownWithFrontmatter>
  )
}
