import assert from 'node:assert/strict'
import test from 'node:test'
import { validateFleetConfig } from '../src/runtime-config.ts'

const page = new URL('http://127.0.0.1:18801/')

test('Fleet runtime config accepts lab and company HTTPS issuers', () => {
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
  const companyPage = new URL('https://fleet.example.invalid/')
  const companyIssuer = 'https://identity.example.invalid/realms/fleet'
  assert.equal(validateFleetConfig({ schema: 1, oidc_issuer: companyIssuer }, companyPage)
    .oidc_issuer, companyIssuer)
  for (const invalid of [
    'http://127.0.0.1:18086/realms/fleet',
    'http://identity.example.invalid/realms/fleet',
    'https://127.0.0.1/realms/fleet',
    'https://identity.example.invalid:8443/realms/fleet',
    'https://user:pass@identity.example.invalid/realms/fleet',
    'https://identity.example.invalid/realms/fleet?next=outside',
    'https://identity.example.invalid/realms/fleet/',
  ]) {
    assert.throws(() => validateFleetConfig({ schema: 1, oidc_issuer: invalid }, companyPage))
  }
})
