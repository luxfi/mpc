export interface Branding {
  brand: string
  logoText: string
  description: string
  iamUrl: string
  iamClientId: string
  iamLabel: string
}

export const brandingConfig: Record<string, Branding> = {
  'mpc.lux.network': {
    brand: 'Lux MPC',
    logoText: 'Lux MPC',
    description: 'Multi-Party Computation Wallet Platform by Lux Network',
    iamUrl: 'https://lux.id',
    iamClientId: 'lux-mpc',
    iamLabel: 'Lux ID',
  },
  'mpc.pars.network': {
    brand: 'Pars MPC',
    logoText: 'Pars MPC',
    description: 'Multi-Party Computation Wallet Platform by Pars Network',
    iamUrl: 'https://pars.id',
    iamClientId: 'pars-mpc',
    iamLabel: 'Pars ID',
  },
  'mpc.zoo.network': {
    brand: 'Zoo MPC',
    logoText: 'Zoo MPC',
    description: 'Multi-Party Computation Wallet Platform by Zoo Network',
    iamUrl: 'https://id.zoo.network',
    iamClientId: 'zoo-mpc',
    iamLabel: 'Zoo ID',
  },
  'cloud.lux.network': {
    brand: 'Lux Cloud',
    logoText: 'Lux Cloud',
    description: 'Cloud Wallet Management by Lux Network',
    iamUrl: 'https://lux.id',
    iamClientId: 'lux-mpc',
    iamLabel: 'Lux ID',
  },
}

const defaultBranding: Branding = brandingConfig['mpc.lux.network']

/** Pure function — works in both server and client contexts. */
export function getBranding(hostname: string): Branding {
  const host = hostname.split(':')[0]
  return brandingConfig[host] ?? defaultBranding
}
