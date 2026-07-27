const { withLuxUi } = require('@luxfi/ui/next')

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  experimental: {
    typedRoutes: false,
  },
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: true,
  },
  async rewrites() {
    if (process.env.NODE_ENV === 'production') return []
    return [
      {
        source: '/v1/:path*',
        destination: 'http://localhost:8081/v1/:path*',
      },
    ]
  },
}

// ONE incantation for the gui engine (transpile list, react-native-web alias,
// platform defines) — see @luxfi/ui/next. Hand-rolling it per surface is how
// two apps end up transpiling different halves of the same engine.
module.exports = withLuxUi(nextConfig)
