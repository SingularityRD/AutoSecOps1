const fs = require("fs")

// Prefer an explicit NEXT_PUBLIC_APP_URL; otherwise use the Vercel deployment URL
const appUrl =
  process.env.NEXT_PUBLIC_APP_URL || `https://${process.env.VERCEL_URL}`

// Write the environment variable to .env.local
fs.writeFileSync(".env.local", `NEXT_PUBLIC_APP_URL=${appUrl}\n`, {
  encoding: "utf8",
})

console.log(`Set NEXT_PUBLIC_APP_URL to ${appUrl}`)
