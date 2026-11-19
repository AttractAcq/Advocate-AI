export type FleetConfig = { schema: 1; oidc_issuer: string | null }

let current: FleetConfig | null = null

export function validateFleetConfig(value: unknown, page: URL): FleetConfig {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid Fleet configuration')
  const record = value as Record<string, unknown>
  if (Object.keys(record).sort().join(',') !== 'oidc_issuer,schema' || record.schema !== 1) {
    throw new Error('Invalid Fleet configuration')
  }
  const localPage = page.hostname === '127.0.0.1' || page.hostname === 'localhost'
  if (!localPage && page.protocol !== 'https:') throw new Error('Secure Fleet origin is required')
  if (record.oidc_issuer === null) {
    if (!localPage) throw new Error('Identity provider is required')
    return { schema: 1, oidc_issuer: null }
  }
  if (typeof record.oidc_issuer !== 'string' || record.oidc_issuer.length > 512) {
    throw new Error('Invalid identity provider')
  }
  let issuer: URL
  try { issuer = new URL(record.oidc_issuer) }
  catch { throw new Error('Invalid identity provider') }
  const realm = /^\/realms\/[A-Za-z0-9_-]{1,80}$/.test(issuer.pathname)
  const labIssuer = localPage && issuer.protocol === 'http:' &&
    issuer.hostname === '127.0.0.1' && Boolean(issuer.port)
  const productionIssuer = page.protocol === 'https:' && issuer.protocol === 'https:' &&
    /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(issuer.hostname) &&
    !/^[0-9.]+$/.test(issuer.hostname) &&
    (issuer.port === '' || issuer.port === '443') &&
    issuer.hostname.split('.').every((part) => part.length <= 63 &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(part))
  if ((!labIssuer && !productionIssuer) || !realm ||
      issuer.username || issuer.password || issuer.search || issuer.hash ||
      issuer.href !== record.oidc_issuer) {
    throw new Error('Invalid identity provider')
  }
  return { schema: 1, oidc_issuer: issuer.href }
}

export async function loadRuntimeConfig(): Promise<FleetConfig> {
  const response = await fetch('/fleet-config.json', {
    cache: 'no-store', credentials: 'same-origin', redirect: 'error',
  })
  if (!response.ok || response.headers.get('content-type')?.split(';')[0].trim() !== 'application/json') {
    throw new Error('Fleet configuration is unavailable')
  }
  const raw = await response.text()
  if (raw.length > 4096) throw new Error('Fleet configuration is too large')
  current = validateFleetConfig(JSON.parse(raw) as unknown, new URL(window.location.href))
  return current
}

export function runtimeConfig(): FleetConfig {
  if (!current) throw new Error('Fleet configuration was not loaded')
  return current
}
