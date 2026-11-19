export type Identity = { id: string; role: string }
export type Source = { document_id: string; collection: string; version: string }
export type StagedUpload = { id: string; filename: string; size: number; sha256: string; created_at: string; status: 'pending' }
export type Citation = Source & { sha256: string; ordinal?: number }
export type SourcePreview = { document_id: string; version: string; sha256: string; ordinal: number; excerpt: string }
export type Turn = {
  message: string
  answer: string
  citations: Citation[]
  mode: string
  workspace: string | null
}
export type ChatResult = Turn & { conversation_id: string; model: string; tool_route: string }
export type AdminStatus = {
  mode: string
  identity: string
  model: string
  read_only_tools: string[]
  write_tools: string[]
}
export type SecurityIncident = { incident_id: string; summary: string; severity: string; timestamp: string }
export type SecurityDetail = {
  incident_id: string
  summary: string
  event: { source: string; action: string; asset_status: string; related_asset_status: string; asset: { hostname: string; owner: string; equipment_class: string } | null }
  suggested_checks: string[]
  confidence: string
  evidence: { event_id: string; index_name: string; index_id: string; timestamp: string; rule_id: string; location: string }[]
}
export type SecurityAnalysis = { analysis: string; notice: string; method: 'local-model' | 'evidence-only'; evidence: SecurityDetail['evidence'] }

export async function api<T>(path: string, token: string | null, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`/api${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init.headers,
    },
    cache: 'no-store',
  })
  let body: Record<string, unknown> = {}
  try { body = await response.json() as Record<string, unknown> } catch { /* offline or invalid response */ }
  if (!response.ok) {
    const detail = typeof body.detail === 'string' ? body.detail : `Request failed (${response.status})`
    throw new Error(detail)
  }
  return body as T
}

export async function stageDocument(token: string, file: File): Promise<StagedUpload> {
  const response = await fetch('/api/documents/stage', {
    method: 'POST', cache: 'no-store', body: file,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/octet-stream', 'X-Filename': file.name },
  })
  const result = await response.json() as { upload?: StagedUpload; detail?: string }
  if (!response.ok || !result.upload) throw new Error(result.detail || `Upload failed (${response.status})`)
  return result.upload
}
