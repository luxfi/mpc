import type { Metadata } from 'next'
import { headers } from 'next/headers'
import { Zen } from '@hanzo/font/sans'
import { ZenMono } from '@hanzo/font/mono'
import { resolveWhiteLabel } from '@luxfi/ui/white-label'
import { Providers } from './providers'
import './globals.css'

// Title from the Host header — the same resolution the client uses, so the tab
// and the chrome can never disagree about which brand this is.
export async function generateMetadata(): Promise<Metadata> {
  const h = await headers()
  const wl = resolveWhiteLabel(h.get('host'))
  return {
    title: `${wl.name} MPC`,
    description: `Multi-Party Computation wallet platform by ${wl.name}`,
  }
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className={`dark ${Zen.variable} ${ZenMono.variable}`}>
      <body className="font-sans min-h-screen bg-background text-foreground antialiased">
        <Providers>
          {children}
        </Providers>
      </body>
    </html>
  )
}
