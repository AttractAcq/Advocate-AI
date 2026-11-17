export type ReceiptInput = {
  code: string
  vessel_code: string
  release_code: string
  observed_on: string
  health: 'healthy' | 'degraded' | 'offline'
  key_id: string
  signature: string
}

export function signedReceiptEnvelope(input: ReceiptInput) {
  return {
    schema_version: 1,
    key_id: input.key_id.trim(),
    receipt: {
      code: input.code.trim(),
      vessel_code: input.vessel_code.trim(),
      release_code: input.release_code.trim(),
      source: 'approved_offline_admin',
      observed_on: input.observed_on,
      health: input.health,
    },
    signature: input.signature.trim(),
  }
}
