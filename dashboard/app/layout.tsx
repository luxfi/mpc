import type { Metadata } from 'next'
import { headers } from 'next/headers'
import { GeistSans } from 'geist/font/sans'
import { GeistMono } from 'geist/font/mono'
import { getBranding } from '@/lib/branding'
import { Providers } from './providers'
import './globals.css'

export async function generateMetadata(): Promise<Metadata> {
  const h = await headers()
  const host = h.get('host') ?? 'mpc.lux.network'
  const b = getBranding(host)
  return { title: b.brand, description: b.description }
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className={`dark ${GeistSans.variable} ${GeistMono.variable}`}>
      <body className="font-sans min-h-screen bg-background text-foreground antialiased">
        <Providers>
          {children}
        </Providers>
      </body>
    </html>
  )
}
