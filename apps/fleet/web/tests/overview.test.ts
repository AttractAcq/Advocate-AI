import assert from 'node:assert/strict'
import test from 'node:test'

import { parseFleetOverview } from '../src/api.ts'

const valid = {
  as_of: '2026-11-19',
  counts: { customer: 1, release: 0, deployment: 1, licence: 1,
    ticket: 0, maintenance: 0, receipt: 0 },
  attention_total: 1,
  attention: [{ kind: 'licence', code: 'LIC-LAB1', customer_code: 'CUST-LAB1',
    vessel_code: 'VSL-LAB1', reason: 'licence_past_end', due_on: '2026-11-18' }],
}

test('Fleet overview accepts bounded scoped metadata', () => {
  assert.deepEqual(parseFleetOverview(valid), valid)
})

test('Fleet overview rejects malformed counts and attention before rendering', () => {
  for (const malformed of [
    [],
    { ...valid, counts: { ...valid.counts, licence: 'all' } },
    { ...valid, attention_total: 0 },
    { ...valid, attention: [{ ...valid.attention[0], reason: 'document_text' }] },
    { ...valid, attention: Array(101).fill(valid.attention[0]) },
  ]) {
    assert.throws(() => parseFleetOverview(malformed), /overview response is invalid/)
  }
})
