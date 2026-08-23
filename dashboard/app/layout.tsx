import type { Metadata } from 'next'
import { headers } from 'next/headers'
import { getBranding } from '@/lib/branding'
import { Providers } from './providers'
import '@hanzo/font/css'
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
    <html lang="en" className="dark">
      <body className="font-sans min-h-screen bg-background text-foreground antialiased">
        <Providers>
          {children}
        </Providers>
      </body>
    </html>
  )
}
