import { render } from "@testing-library/react"
import { Response } from "@/components/ai-elements/response"
import { Messages } from "@/components/chat/messages"
import {
  FORM_MARKDOWN_URL_POLICY,
  FormMarkdown,
} from "@/components/forms/form-markdown"
import {
  DEFAULT_MARKDOWN_ORIGIN,
  getStreamdownRehypePlugins,
  type StreamdownRehypePlugins,
} from "@/lib/sanitize-markdown"

// Run the real sanitizer; rehype-raw and rehype-katex stay mocked, so each
// test hands the pipeline the elements raw HTML or markdown would produce.
jest.unmock("rehype-sanitize")

jest.mock("@/lib/query", () => ({
  useQueryClient: () => ({}),
}))

// The chat avatar is a static import that Jest stubs without a `src`.
jest.mock("next/image", () => ({
  __esModule: true,
  default: () => null,
}))

const streamdownProps = jest.fn()

jest.mock("streamdown", () => ({
  Streamdown: (props: Record<string, unknown>) => {
    streamdownProps(props)
    return <div data-testid="streamdown">{props.children as string}</div>
  },
  defaultRehypePlugins: {},
  defaultRemarkPlugins: {},
}))

type HastNode = {
  type: string
  tagName?: string
  value?: string
  children?: HastNode[]
  properties?: Record<string, unknown>
}

type Transformer = (tree: HastNode) => HastNode | undefined

type Pluggable = StreamdownRehypePlugins[number]

function text(value: string): HastNode {
  return { type: "text", value }
}

function link(href: string, label = "label"): HastNode {
  return {
    type: "element",
    tagName: "a",
    properties: { href },
    children: [text(label)],
  }
}

function image(src: string, alt = "chart"): HastNode {
  return {
    type: "element",
    tagName: "img",
    properties: { src, alt },
    children: [],
  }
}

/** Run a rehype plugin list the way unified would, on one paragraph. */
function runPipeline(
  plugins: StreamdownRehypePlugins,
  node: HastNode
): HastNode {
  let tree: HastNode = {
    type: "root",
    children: [{ type: "element", tagName: "p", children: [node] }],
  }
  for (const entry of plugins as Pluggable[]) {
    const [plugin, options] = Array.isArray(entry) ? entry : [entry]
    const transform = (plugin as (options?: unknown) => Transformer)(options)
    tree = transform(tree) ?? tree
  }
  return tree.children?.[0]?.children?.[0] as HastNode
}

function lastRehypePlugins(): StreamdownRehypePlugins {
  const props = streamdownProps.mock.calls.at(-1)?.[0]
  expect(props.rehypePlugins).toBeDefined()
  return props.rehypePlugins as StreamdownRehypePlugins
}

function expectBlockedLink(node: HastNode) {
  expect(node.tagName).toBe("span")
  expect(node.properties?.href).toBeUndefined()
  expect(JSON.stringify(node)).toContain("[blocked]")
}

function expectBlockedImage(node: HastNode) {
  expect(node.tagName).toBe("span")
  expect(node.properties?.src).toBeUndefined()
  expect(JSON.stringify(node)).toContain("[Image blocked: chart]")
}

const UNSAFE_URLS = [
  "javascript:alert(1)",
  "JaVaScRiPt:alert(1)",
  "data:text/html,<script>alert(1)</script>",
  "vbscript:msgbox(1)",
  "file:///etc/passwd",
]

function chatSites(): Array<[string, () => StreamdownRehypePlugins]> {
  return [
    ["the shared helper", () => getStreamdownRehypePlugins()],
    [
      "Response",
      () => {
        render(<Response>text</Response>)
        return lastRehypePlugins()
      },
    ],
    [
      "Messages (persisted)",
      () => {
        render(
          <Messages
            messages={[
              {
                kind: "response",
                parts: [{ part_kind: "text", content: "text" }],
              },
            ]}
            isResponding={false}
            entityType="case"
            entityId="entity"
            workspaceId="workspace"
          />
        )
        return lastRehypePlugins()
      },
    ],
    [
      "Messages (streaming)",
      () => {
        render(
          <Messages
            messages={[]}
            isResponding
            entityType="case"
            entityId="entity"
            workspaceId="workspace"
            streamingText="text"
          />
        )
        return lastRehypePlugins()
      },
    ],
  ]
}

describe("chat markdown URL hardening", () => {
  beforeEach(() => streamdownProps.mockClear())

  describe.each(chatSites())("%s", (_name, getPlugins) => {
    it("keeps an https link and opens it without an opener", () => {
      const node = runPipeline(getPlugins(), link("https://example.com/docs"))
      expect(node.tagName).toBe("a")
      expect(node.properties).toMatchObject({
        href: "https://example.com/docs",
        target: "_blank",
        rel: "noopener noreferrer",
      })
    })

    it("keeps a path-relative link relative", () => {
      const node = runPipeline(getPlugins(), link("/workspaces"))
      expect(node.properties?.href).toBe("/workspaces")
    })

    it.each(UNSAFE_URLS)("blocks a %s link", (href) => {
      expectBlockedLink(runPipeline(getPlugins(), link(href)))
    })

    it("keeps an https image", () => {
      const node = runPipeline(
        getPlugins(),
        image("https://img.example.com/p.png")
      )
      expect(node.tagName).toBe("img")
      expect(node.properties?.src).toBe("https://img.example.com/p.png")
    })

    it.each([
      "javascript:alert(1)",
      "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=",
      "data:image/png;base64,iVBORw0KGgo=",
    ])("blocks a %s image", (src) => {
      expectBlockedImage(runPipeline(getPlugins(), image(src)))
    })
  })

  it("runs exactly one URL hardening step, with our options", () => {
    const plugins = getStreamdownRehypePlugins() as Pluggable[]
    const hardenEntries = plugins.filter(
      (entry) =>
        Array.isArray(entry) &&
        typeof entry[1] === "object" &&
        entry[1] !== null &&
        "allowedLinkPrefixes" in entry[1]
    )
    expect(hardenEntries).toHaveLength(1)
    expect((hardenEntries[0] as [unknown, unknown])[1]).toEqual({
      defaultOrigin: DEFAULT_MARKDOWN_ORIGIN,
      allowedLinkPrefixes: ["*"],
      allowedImagePrefixes: ["*"],
      allowDataImages: false,
      allowedProtocols: [],
    })
  })
})

describe("narrower URL policies", () => {
  it("only allows link prefixes on the listed origin", () => {
    const plugins = getStreamdownRehypePlugins({
      allowedLinkPrefixes: ["https://docs.example.com/"],
      allowedImagePrefixes: ["https://img.example.com/"],
    })

    expect(
      runPipeline(plugins, link("https://docs.example.com/guide")).properties
        ?.href
    ).toBe("https://docs.example.com/guide")
    expectBlockedLink(
      runPipeline(plugins, link("https://attacker.example.net/phish"))
    )
    expectBlockedLink(
      runPipeline(plugins, link("https://docs.example.com.attacker.net/"))
    )
    expect(
      runPipeline(plugins, image("https://img.example.com/a.png")).properties
        ?.src
    ).toBe("https://img.example.com/a.png")
    expectBlockedImage(
      runPipeline(plugins, image("https://tracker.example.net/pixel.gif"))
    )
  })
})

describe("form markdown URL hardening", () => {
  beforeEach(() => streamdownProps.mockClear())

  function formPlugins(): StreamdownRehypePlugins {
    render(<FormMarkdown>text</FormMarkdown>)
    return lastRehypePlugins()
  }

  it("uses the form policy: links through, no images", () => {
    expect(FORM_MARKDOWN_URL_POLICY).toEqual({
      allowedLinkPrefixes: ["*"],
      allowedImagePrefixes: [],
    })
  })

  it("keeps an https link", () => {
    const node = runPipeline(formPlugins(), link("https://example.com/form"))
    expect(node.tagName).toBe("a")
    expect(node.properties?.href).toBe("https://example.com/form")
  })

  it.each(UNSAFE_URLS)("blocks a %s link", (href) => {
    expectBlockedLink(runPipeline(formPlugins(), link(href)))
  })

  it.each([
    "https://img.example.com/p.png",
    "data:image/png;base64,iVBORw0KGgo=",
  ])("blocks every image, including %s", (src) => {
    expectBlockedImage(runPipeline(formPlugins(), image(src)))
  })
})
