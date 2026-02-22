import { NextResponse, type NextRequest } from 'next/server'

// Public paths — accessible without authentication
const PUBLIC_PATHS = [
  '/login',
  '/auth/callback',
  '/api',
  '/healthz',
]

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  // Allow public paths without auth check
  if (PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(p + '/'))) {
    return NextResponse.next()
  }

  // Check for session cookie set by auth.ts setTokens()
  const session = request.cookies.get('lux_mpc_session')
  if (!session?.value) {
    const loginUrl = new URL('/login', request.url)
    loginUrl.searchParams.set('from', pathname)
    return NextResponse.redirect(loginUrl)
  }

  return NextResponse.next()
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)'],
}
