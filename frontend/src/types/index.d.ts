export type SiteConfig = {
  name: string
  author: string
  description: string
  keywords: Array<string>
  url: {
    base: string
    author: string
  }
  links: {
    docs: string
    support: string
    sales: string
  }
  ogImage: string
}
