import assert from 'node:assert/strict'
import test from 'node:test'
import { signedReceiptEnvelope } from '../src/receipt.ts'

test('signed receipt entry sends only the approved metadata envelope', () => {
  const envelope = signedReceiptEnvelope({
    code: ' RCP-LAB1 ', vessel_code: 'VSL-LAB1', release_code: 'REL-LAB1',
    observed_on: '2026-11-17', health: 'healthy', key_id: 'a'.repeat(64),
    signature: 'b'.repeat(88), document: 'do-not-send',
  } as Parameters<typeof signedReceiptEnvelope>[0])
  assert.equal(envelope.schema_version, 1)
  assert.equal(envelope.receipt.code, 'RCP-LAB1')
  assert.equal(envelope.receipt.source, 'approved_offline_admin')
  assert.equal(Object.hasOwn(envelope.receipt, 'document'), false)
  assert.deepEqual(Object.keys(envelope).sort(), ['key_id', 'receipt', 'schema_version', 'signature'])
})
