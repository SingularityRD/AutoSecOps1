import { neutralizeUntrustedText } from "@/lib/robodr"
import { cn } from "@/lib/utils"

/** Props for {@link UntrustedValue}. */
export interface UntrustedValueProps {
  /** Adversary-controlled text, exactly as stored. */
  value: string
  className?: string
}

/**
 * Renders an adversary-controlled value as inert plain text.
 *
 * The value goes through {@link neutralizeUntrustedText} and is placed in a
 * React text node inside a `<code>` element, so it is never parsed as HTML,
 * Markdown or a link, and invisible or reordering characters show as visible
 * `[U+XXXX]` markers.
 */
export function UntrustedValue({ value, className }: UntrustedValueProps) {
  const { text, truncated } = neutralizeUntrustedText(value)
  return (
    <code
      data-untrusted="true"
      className={cn(
        "whitespace-pre-wrap break-all rounded border border-dashed border-amber-500/50 bg-amber-50/50 px-1 py-0.5 font-mono text-xs text-foreground dark:bg-amber-950/20",
        className
      )}
    >
      <span className="sr-only">Untrusted value: </span>
      {text}
      {truncated ? (
        <span className="text-muted-foreground"> (truncated)</span>
      ) : null}
    </code>
  )
}
