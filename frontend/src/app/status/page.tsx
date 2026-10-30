import Image from "next/image"
import AutoSecOpsIcon from "public/icon.png"
import { AlertNotification } from "@/components/notifications"
import { siteConfig } from "@/config/site"

export default async function Page() {
  return (
    <main className="container flex size-full max-w-[400px] flex-col items-center justify-center space-y-4">
      <Image src={AutoSecOpsIcon} alt="AutoSecOps" className="mb-8 size-16" />
      <h1 className="text-lg font-semibold">
        We&apos;re sorry for the inconvenience.
      </h1>
      <AlertNotification
        level="info"
        className="text-2xl font-medium"
        message="Our site is currently down. We'll be back up in 1-2 hours. Please contact info@singularityrd.com for
        updates."
      />
      <div className="flex items-center justify-center space-x-4">
        <a
          href={siteConfig.links.support}
          className="text-sm text-muted-foreground underline"
        >
          Contact support
        </a>
      </div>
    </main>
  )
}
