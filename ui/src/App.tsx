import { Router, Route, Switch, Link, useLocation } from 'wouter'
import { useHashLocation } from 'wouter/use-hash-location'
import { Dashboard } from './pages/Dashboard'
import { Wallets } from './pages/Wallets'
import { Vaults } from './pages/Vaults'
import { Policies } from './pages/Policies'
import { Settlements } from './pages/Settlements'
import { Bridge } from './pages/Bridge'
import { Payments } from './pages/Payments'
import { Audit } from './pages/Audit'
import { Settings } from './pages/Settings'

const navItems = [
  { href: '/', label: 'Dashboard' },
  { href: '/wallets', label: 'Wallets' },
  { href: '/vaults', label: 'Vaults' },
  { href: '/policies', label: 'Policies' },
  { href: '/settlements', label: 'Settlements' },
  { href: '/bridge', label: 'Bridge' },
  { href: '/payments', label: 'Payments' },
  { href: '/audit', label: 'Audit' },
  { href: '/settings', label: 'Settings' },
] as const

function NavLink({ href, label }: { href: string; label: string }) {
  const [location] = useLocation()
  const active = href === '/' ? location === '/' : location.startsWith(href)
  return (
    <Link
      href={href}
      style={{
        display: 'block',
        padding: '6px 12px',
        borderRadius: 6,
        color: active ? '#fff' : '#a3a3a3',
        background: active ? '#262626' : 'transparent',
        textDecoration: 'none',
        fontSize: 14,
      }}
    >
      {label}
    </Link>
  )
}

export function App() {
  return (
    <Router hook={useHashLocation}>
      <div style={{ display: 'flex', height: '100vh', background: '#000', color: '#e5e5e5' }}>
        <aside
          style={{
            width: 200,
            borderRight: '1px solid #262626',
            padding: 16,
            display: 'flex',
            flexDirection: 'column',
            gap: 2,
            flexShrink: 0,
          }}
        >
          <div style={{ fontWeight: 600, fontSize: 16, marginBottom: 16, color: '#fff' }}>
            MPC Admin
          </div>
          <nav style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            {navItems.map((n) => (
              <NavLink key={n.href} href={n.href} label={n.label} />
            ))}
          </nav>
        </aside>
        <main style={{ flex: 1, overflow: 'auto', padding: 24 }}>
          <Switch>
            <Route path="/" component={Dashboard} />
            <Route path="/wallets" component={Wallets} />
            <Route path="/vaults" component={Vaults} />
            <Route path="/policies" component={Policies} />
            <Route path="/settlements" component={Settlements} />
            <Route path="/bridge" component={Bridge} />
            <Route path="/payments" component={Payments} />
            <Route path="/audit" component={Audit} />
            <Route path="/settings" component={Settings} />
            <Route>
              <div style={{ color: '#737373' }}>Not found</div>
            </Route>
          </Switch>
        </main>
      </div>
    </Router>
  )
}
