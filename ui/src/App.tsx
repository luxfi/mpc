import { Router, Route, Switch, Link, useLocation, Redirect } from 'wouter'
import { useHashLocation } from 'wouter/use-hash-location'
import { auth } from './lib/api'
import { Login } from './pages/Login'
import { Dashboard } from './pages/Dashboard'
import { Operations } from './pages/Operations'
import { Sign } from './pages/Sign'
import { Wallets } from './pages/Wallets'
import { Vaults } from './pages/Vaults'
import { Policies } from './pages/Policies'
import { Whitelist } from './pages/Whitelist'
import { Settlements } from './pages/Settlements'
import { Bridge } from './pages/Bridge'
import { Payments } from './pages/Payments'
import { Audit } from './pages/Audit'
import { Devices } from './pages/Devices'
import { Webhooks } from './pages/Webhooks'
import { APIKeys } from './pages/APIKeys'
import { Users } from './pages/Users'
import { Settings } from './pages/Settings'

type NavItem = { href: string; label: string }
type NavGroup = { title: string; items: NavItem[] }

const groups: NavGroup[] = [
  {
    title: 'Treasury',
    items: [
      { href: '/', label: 'Dashboard' },
      { href: '/operations', label: 'Operations' },
      { href: '/sign', label: 'New transaction' },
    ],
  },
  {
    title: 'Wallets',
    items: [
      { href: '/wallets', label: 'Wallets' },
      { href: '/vaults', label: 'Vaults' },
      { href: '/whitelist', label: 'Allowlist' },
    ],
  },
  {
    title: 'Governance',
    items: [
      { href: '/policies', label: 'Policies' },
      { href: '/users', label: 'Users' },
      { href: '/devices', label: 'Devices' },
    ],
  },
  {
    title: 'Pipeline',
    items: [
      { href: '/settlements', label: 'Settlements' },
      { href: '/bridge', label: 'Bridge' },
      { href: '/payments', label: 'Payments' },
    ],
  },
  {
    title: 'System',
    items: [
      { href: '/audit', label: 'Audit log' },
      { href: '/api-keys', label: 'API keys' },
      { href: '/webhooks', label: 'Webhooks' },
      { href: '/settings', label: 'Settings' },
    ],
  },
]

function NavLink({ href, label }: NavItem) {
  const [location] = useLocation()
  const active = href === '/' ? location === '/' : location.startsWith(href)
  return (
    <Link
      href={href}
      style={{
        display: 'block',
        padding: '5px 12px',
        borderRadius: 6,
        color: active ? '#fff' : '#a3a3a3',
        background: active ? '#262626' : 'transparent',
        textDecoration: 'none',
        fontSize: 13,
      }}
    >
      {label}
    </Link>
  )
}

function Sidebar() {
  const me = auth.user()
  function logout() {
    auth.clear()
    window.location.hash = '#/login'
  }
  return (
    <aside
      style={{
        width: 220,
        borderRight: '1px solid #262626',
        padding: 16,
        display: 'flex',
        flexDirection: 'column',
        gap: 12,
        flexShrink: 0,
        overflowY: 'auto',
      }}
    >
      <div>
        <div style={{ fontWeight: 600, fontSize: 16, color: '#fff' }}>MPC Admin</div>
        {me && (
          <div style={{ fontSize: 11, color: '#737373', marginTop: 2 }}>
            {me.email} · {me.role}
          </div>
        )}
      </div>
      {groups.map((g) => (
        <nav key={g.title} style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
          <div style={{
            fontSize: 10,
            color: '#525252',
            textTransform: 'uppercase',
            letterSpacing: '0.08em',
            padding: '4px 12px',
          }}>
            {g.title}
          </div>
          {g.items.map((n) => <NavLink key={n.href} {...n} />)}
        </nav>
      ))}
      <button
        onClick={logout}
        style={{
          marginTop: 'auto',
          background: 'transparent',
          border: '1px solid #262626',
          borderRadius: 6,
          padding: '6px 12px',
          color: '#a3a3a3',
          fontSize: 12,
          cursor: 'pointer',
        }}
      >
        Sign out
      </button>
    </aside>
  )
}

function Protected({ children }: { children: React.ReactNode }) {
  const tok = auth.token()
  if (!tok) return <Redirect to="/login" />
  return <>{children}</>
}

export function App() {
  return (
    <Router hook={useHashLocation}>
      <Switch>
        <Route path="/login" component={Login} />
        <Route>
          <Protected>
            <div style={{ display: 'flex', height: '100vh', background: '#000', color: '#e5e5e5' }}>
              <Sidebar />
              <main style={{ flex: 1, overflow: 'auto', padding: 24 }}>
                <Switch>
                  <Route path="/" component={Dashboard} />
                  <Route path="/operations" component={Operations} />
                  <Route path="/sign" component={Sign} />
                  <Route path="/wallets" component={Wallets} />
                  <Route path="/vaults" component={Vaults} />
                  <Route path="/whitelist" component={Whitelist} />
                  <Route path="/policies" component={Policies} />
                  <Route path="/users" component={Users} />
                  <Route path="/devices" component={Devices} />
                  <Route path="/settlements" component={Settlements} />
                  <Route path="/bridge" component={Bridge} />
                  <Route path="/payments" component={Payments} />
                  <Route path="/audit" component={Audit} />
                  <Route path="/api-keys" component={APIKeys} />
                  <Route path="/webhooks" component={Webhooks} />
                  <Route path="/settings" component={Settings} />
                  <Route>
                    <div style={{ color: '#737373' }}>Not found</div>
                  </Route>
                </Switch>
              </main>
            </div>
          </Protected>
        </Route>
      </Switch>
    </Router>
  )
}
