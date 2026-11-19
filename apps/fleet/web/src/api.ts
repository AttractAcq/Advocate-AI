export type FleetRow = Record<string, string | number | null>
export type FleetAuthMode = 'lab' | 'oidc'

export async function fleetApi<T>(path: string, token: string, init?: RequestInit,
                                  mode: FleetAuthMode = 'lab'): Promise<T> {
  if (!path.startsWith('/api/fleet/') || path.includes('..')) {
    throw new Error('Invalid Fleet API path')
  }
  const response = await fetch(path, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(mode === 'oidc' ? { Authorization: `Bearer ${token}` } : { 'X-Fleet-Lab-Token': token }),
      ...init?.headers,
    },
    cache: 'no-store',
    credentials: 'omit',
  })
  if (!response.ok) {
    if (response.status === 401) throw new Error('Fleet authentication was rejected')
    const detail = await response.json().catch(() => null) as { detail?: string } | null
    throw new Error(typeof detail?.detail === 'string' ? detail.detail : `Fleet request failed (${response.status})`)
  }
  return response.json() as Promise<T>
}
