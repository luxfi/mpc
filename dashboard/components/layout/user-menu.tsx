'use client'

import { useState, useRef, useEffect } from 'react'
import Link from 'next/link'
import { clearTokens } from '@/lib/auth'

export function UserMenu() {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (ref.current && !ref.current.contains(event.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const handleLogout = () => {
    clearTokens()
    window.location.href = '/login'
  }

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground"
      >
        <div className="flex h-7 w-7 items-center justify-center rounded-full bg-muted text-xs font-semibold text-muted-foreground">
          U
        </div>
        <span className="hidden sm:inline">user@example.com</span>
        <svg
          className={`h-4 w-4 transition-transform ${open ? 'rotate-180' : ''}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && (
        <div className="absolute right-0 mt-1 w-48 rounded-md border border-border bg-card p-1 shadow-lg">
          <Link
            href="/settings"
            onClick={() => setOpen(false)}
            className="block rounded-sm px-3 py-2 text-sm text-card-foreground hover:bg-accent"
          >
            Profile
          </Link>
          <Link
            href="/settings"
            onClick={() => setOpen(false)}
            className="block rounded-sm px-3 py-2 text-sm text-card-foreground hover:bg-accent"
          >
            Settings
          </Link>
          <hr className="my-1 border-border" />
          <button
            onClick={handleLogout}
            className="block w-full rounded-sm px-3 py-2 text-left text-sm text-destructive hover:bg-accent"
          >
            Logout
          </button>
        </div>
      )}
    </div>
  )
}
