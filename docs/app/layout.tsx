import "./global.css"
import { RootProvider } from "fumadocs-ui/provider/next"
import { GeistSans } from "geist/font/sans"
import { GeistMono } from "geist/font/mono"
import type { ReactNode } from "react"

export const metadata = {
  title: {
    default: "Lux MPC - Threshold Signature Documentation",
    template: "%s | Lux MPC",
  },
  description: "Multi-Party Computation for threshold signatures - ECDSA, EdDSA, and Taproot",
}

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <html
      lang="en"
      className={`${GeistSans.variable} ${GeistMono.variable}`}
      suppressHydrationWarning
    >
      <body className="min-h-svh bg-background font-sans antialiased">
        <RootProvider
          search={{
            enabled: true,
          }}
          theme={{
            enabled: true,
            defaultTheme: "dark",
          }}
        >
          <div className="relative flex min-h-svh flex-col bg-background">
            {children}
          </div>
        </RootProvider>
      </body>
    </html>
  )
}
