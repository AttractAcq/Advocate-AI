import assert from 'node:assert/strict'
import test from 'node:test'
import { validateFleetConfig } from '../src/runtime-config.ts'

const page = new URL('http://127.0.0.1:18801/')

test('Fleet runtime config accepts only the local lab issuer', () => {
  assert.equal(validateFleetConfig({ schema: 1, oidc_issuer: null }, page).oidc_issuer, null)
  const issuer = 'http://127.0.0.1:18086/realms/fleet-lab'
  assert.equal(validateFleetConfig({ schema: 1, oidc_issuer: issuer }, page).oidc_issuer, issuer)
  for (const invalid of [
    'https://identity.example.invalid/realms/fleet',
    'http://localhost:18086/realms/fleet-lab',
    'http://127.0.0.1:18086/not-a-realm',
    'http://127.0.0.1:18086/realms/fleet-lab?redirect=outside',
  ]) {
    assert.throws(() => validateFleetConfig({ schema: 1, oidc_issuer: invalid }, page))
  }
  assert.throws(() => validateFleetConfig({ schema: 1, oidc_issuer: null },
                                             new URL('https://fleet.example.invalid/')))
})
