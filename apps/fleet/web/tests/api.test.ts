import assert from 'node:assert/strict'
import test from 'node:test'
import { fleetApi } from '../src/api.ts'

test('Fleet requests stay on the same-origin API and omit browser credentials', async () => {
  const original = globalThis.fetch
  let calls = 0
  globalThis.fetch = async (input, init) => {
    calls += 1
    assert.equal(input, '/api/fleet/customers')
    assert.equal(init?.credentials, 'omit')
    assert.equal(init?.cache, 'no-store')
    assert.equal((init?.headers as Record<string, string>)['X-Fleet-Lab-Token'], 'lab-token')
    return new Response(JSON.stringify([{ code: 'CUST-LAB1' }]), { status: 200 })
  }
  try {
    const rows = await fleetApi<{ code: string }[]>('/api/fleet/customers', 'lab-token')
    assert.equal(rows[0].code, 'CUST-LAB1')
    await assert.rejects(fleetApi('https://example.invalid/api/fleet/customers', 'lab-token'))
    await assert.rejects(fleetApi('/api/fleet/../secret', 'lab-token'))
    assert.equal(calls, 1)
  } finally {
    globalThis.fetch = original
  }
})

test('OIDC mode sends a bearer token without the shared lab header', async () => {
  const original = globalThis.fetch
  globalThis.fetch = async (_input, init) => {
    const headers = init?.headers as Record<string, string>
    assert.equal(headers.Authorization, 'Bearer signed-access-token')
    assert.equal(Object.hasOwn(headers, 'X-Fleet-Lab-Token'), false)
    return new Response(JSON.stringify({ id: 'viewer', role: 'fleet_viewer' }), { status: 200 })
  }
  try {
    const me = await fleetApi<{ role: string }>('/api/fleet/me', 'signed-access-token',
                                                undefined, 'oidc')
    assert.equal(me.role, 'fleet_viewer')
  } finally {
    globalThis.fetch = original
  }
})
