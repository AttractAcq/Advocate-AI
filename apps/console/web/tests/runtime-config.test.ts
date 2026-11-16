import assert from 'node:assert/strict'
import { test } from 'node:test'
import { loadRuntimeConfig, validateConsoleConfig } from '../src/runtime-config.ts'

const lab = new URL('http://127.0.0.1:18101/')
const vessel = new URL('https://console.vessel.example/')

test('one build accepts a local OIDC issuer or a separate HTTPS vessel issuer', () => {
  assert.deepEqual(validateConsoleConfig({ schema: 1, oidc_issuer: null }, lab),
    { schema: 1, oidc_issuer: null })
  assert.deepEqual(validateConsoleConfig({ schema: 1,
    oidc_issuer: 'http://127.0.0.1:18086/realms/sovereign-lab' }, lab),
  { schema: 1, oidc_issuer: 'http://127.0.0.1:18086/realms/sovereign-lab' })
  assert.deepEqual(validateConsoleConfig({ schema: 1,
    oidc_issuer: 'https://identity.vessel.example/realms/sovereign' }, vessel),
  { schema: 1, oidc_issuer: 'https://identity.vessel.example/realms/sovereign' })
})

test('invalid or insecure deployment configuration fails closed', () => {
  const invalid: Array<[unknown, URL]> = [
    [{ schema: 1, oidc_issuer: null }, vessel],
    [{ schema: 1, oidc_issuer: 'http://identity.vessel.example/realms/vessel' }, vessel],
    [{ schema: 1, oidc_issuer: 'http://127.0.0.1:18086/realms/lab' }, vessel],
    [{ schema: 1, oidc_issuer: 'https://user:secret@identity.vessel.example/realms/vessel' }, vessel],
    [{ schema: 1, oidc_issuer: 'https://identity.vessel.example/realms/vessel?next=elsewhere' }, vessel],
    [{ schema: 1, oidc_issuer: 'https://identity.vessel.example/realms/vessel#fragment' }, vessel],
    [{ schema: 1, oidc_issuer: 'https://identity.vessel.example/' }, vessel],
    [{ schema: 1, oidc_issuer: null, token: 'do-not-expose' }, lab],
    [{ schema: true, oidc_issuer: null }, lab],
    [{ schema: 1, oidc_issuer: null }, new URL('http://console.vessel.example/')],
  ]
  for (const [config, page] of invalid) assert.throws(() => validateConsoleConfig(config, page))
})

test('runtime loader requires same-origin JSON and disables cache and redirects', async () => {
  const originalFetch = globalThis.fetch
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, 'window')
  Object.defineProperty(globalThis, 'window', { configurable: true,
    value: { location: { href: lab.href } } })
  try {
    globalThis.fetch = async (input, init) => {
      assert.equal(input, '/console-config.json')
      assert.equal(init?.cache, 'no-store')
      assert.equal(init?.redirect, 'error')
      return new Response('{"schema":1,"oidc_issuer":null}',
        { headers: { 'content-type': 'application/json; charset=utf-8' } })
    }
    assert.deepEqual(await loadRuntimeConfig(), { schema: 1, oidc_issuer: null })
    globalThis.fetch = async () => new Response('<html>fallback</html>',
      { headers: { 'content-type': 'text/html' } })
    await assert.rejects(loadRuntimeConfig())
  } finally {
    globalThis.fetch = originalFetch
    if (originalWindow) Object.defineProperty(globalThis, 'window', originalWindow)
    else Reflect.deleteProperty(globalThis, 'window')
  }
})
