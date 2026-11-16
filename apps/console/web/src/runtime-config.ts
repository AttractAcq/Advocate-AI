export type ConsoleConfig = { schema: 1; oidc_issuer: string | null }

let current: ConsoleConfig | null = null

export function validateConsoleConfig(value: unknown, page: URL): ConsoleConfig {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid Console configuration')
  const record = value as Record<string, unknown>
  if (Object.keys(record).sort().join(',') !== 'oidc_issuer,schema' || record.schema !== 1) {
    throw new Error('Invalid Console configuration')
  }
  const localPage = page.hostname === '127.0.0.1' || page.hostname === 'localhost'
  if (!localPage && page.protocol !== 'https:') throw new Error('Secure Console origin is required')
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
  const localIssuer = issuer.hostname === '127.0.0.1' || issuer.hostname === 'localhost'
  if ((issuer.protocol !== 'https:' && !(localPage && localIssuer && issuer.protocol === 'http:')) ||
      issuer.username || issuer.password || issuer.search || issuer.hash ||
      issuer.pathname === '/' || issuer.href !== record.oidc_issuer ||
      issuer.pathname.endsWith('/')) {
    throw new Error('Invalid identity provider')
  }
  return { schema: 1, oidc_issuer: issuer.href }
}

export async function loadRuntimeConfig(): Promise<ConsoleConfig> {
  const response = await fetch('/console-config.json', {
    cache: 'no-store', credentials: 'same-origin', redirect: 'error',
  })
  if (!response.ok || response.headers.get('content-type')?.split(';')[0].trim() !== 'application/json') {
    throw new Error('Console configuration is unavailable')
  }
  const raw = await response.text()
  if (raw.length > 4096) throw new Error('Console configuration is too large')
  current = validateConsoleConfig(JSON.parse(raw) as unknown, new URL(window.location.href))
  return current
}

export function runtimeConfig(): ConsoleConfig {
  if (!current) throw new Error('Console configuration was not loaded')
  return current
}
