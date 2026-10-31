import { render, screen } from "@testing-library/react"
import {
  FORM_MARKDOWN_URL_POLICY,
  FormMarkdown,
  FormMarkdownLink,
} from "@/components/forms/form-markdown"
import { remarkFormMarkdown } from "@/lib/forms/markdown"
import { getStreamdownRehypePlugins } from "@/lib/sanitize-markdown"

const streamdownProps = jest.fn()

jest.mock("streamdown", () => ({
  Streamdown: (props: Record<string, unknown>) => {
    streamdownProps(props)
    return <div data-testid="streamdown">{props.children as string}</div>
  },
  defaultRehypePlugins: {},
  defaultRemarkPlugins: {},
}))

describe("FormMarkdownLink", () => {
  it.each(["https://example.com/docs", "mailto:it@example.com"])(
    "links to %s in a new tab without an opener",
    (href) => {
      render(<FormMarkdownLink href={href}>label</FormMarkdownLink>)
      const anchor = screen.getByRole("link", { name: "label" })
      expect(anchor).toHaveAttribute("href", href)
      expect(anchor).toHaveAttribute("target", "_blank")
      expect(anchor).toHaveAttribute("rel", "noopener noreferrer")
    }
  )

  it.each([
    "javascript:alert(1)",
    "data:text/html,x",
    "/workspaces",
    undefined,
  ])("renders %p as plain text", (href) => {
    render(<FormMarkdownLink href={href}>label</FormMarkdownLink>)
    expect(screen.queryByRole("link")).not.toBeInTheDocument()
    expect(screen.getByText("label")).toBeInTheDocument()
  })
})

describe("FormMarkdown", () => {
  it("filters the markdown tree before any HTML exists and shows no image", () => {
    render(<FormMarkdown>Request a **laptop**.</FormMarkdown>)

    expect(screen.getByTestId("streamdown")).toHaveTextContent(
      "Request a **laptop**."
    )
    const props = streamdownProps.mock.calls.at(-1)?.[0]
    // Remark plugins run before the raw-HTML parser in the rehype list, so
    // dropped HTML never reaches it. The form filter runs last.
    expect(props.remarkPlugins.at(-1)).toBe(remarkFormMarkdown)
    // Our list replaces Streamdown's default rehype plugins, including its
    // permissive URL hardening.
    expect(props.rehypePlugins).toEqual(
      getStreamdownRehypePlugins(FORM_MARKDOWN_URL_POLICY)
    )
    expect(props.components.a).toBe(FormMarkdownLink)
    expect(props.components.img({})).toBeNull()
  })
})
