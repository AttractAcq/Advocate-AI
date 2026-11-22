export type FleetRow = Record<string, string | number | null>
export type FleetAuthMode = 'lab' | 'oidc'
export type RecordKind = 'customer' | 'release' | 'deployment' | 'licence' |
  'ticket' | 'maintenance' | 'receipt'
export type FleetOverview = { as_of: string; counts: Record<RecordKind, number>;
  attention_total: number; attention: { kind: RecordKind; code: string;
    customer_code: string; vessel_code: string; reason: string; due_on: string | null }[] }

const recordKinds: RecordKind[] = ['customer', 'release', 'deployment', 'licence',
  'ticket', 'maintenance', 'receipt']
const attentionReasons = new Set(['licence_not_started', 'licence_past_end',
  'licence_ends_soon', 'maintenance_overdue', 'urgent_support'])

export function parseFleetOverview(value: unknown): FleetOverview {
  const invalid = () => { throw new Error('Fleet overview response is invalid') }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return invalid()
  const item = value as Record<string, unknown>
  if (typeof item.as_of !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(item.as_of) ||
      !item.counts || typeof item.counts !== 'object' || Array.isArray(item.counts) ||
      !Array.isArray(item.attention) || item.attention.length > 100 ||
      typeof item.attention_total !== 'number' ||
      !Number.isSafeInteger(item.attention_total) || item.attention_total < item.attention.length ||
      Object.keys(item.counts).length !== recordKinds.length ||
      !recordKinds.every((kind) => {
        const count = (item.counts as Record<string, unknown>)[kind]
        return typeof count === 'number' && Number.isSafeInteger(count) && count >= 0
      })) return invalid()
  for (const entry of item.attention) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return invalid()
    const row = entry as Record<string, unknown>
    if (!recordKinds.includes(row.kind as RecordKind) ||
        !['licence', 'ticket', 'maintenance'].includes(String(row.kind)) ||
        !attentionReasons.has(String(row.reason)) ||
        !['code', 'customer_code', 'vessel_code'].every((key) =>
          typeof row[key] === 'string' && (row[key] as string).length > 0 &&
          (row[key] as string).length <= 32) ||
        !(row.due_on === null || (typeof row.due_on === 'string' &&
          /^\d{4}-\d{2}-\d{2}$/.test(row.due_on)))) return invalid()
  }
  return value as FleetOverview
}

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
