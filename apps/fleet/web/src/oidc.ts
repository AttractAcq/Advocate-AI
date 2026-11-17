import { runtimeConfig } from './runtime-config'

function configuredIssuer(): string | null { return runtimeConfig().oidc_issuer }
const clientId = 'sovereign-fleet-portal'

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

export function oidcEnabled(): boolean { return Boolean(configuredIssuer()) }

export async function beginOidc(): Promise<void> {
  const issuer = configuredIssuer()
  if (!issuer) throw new Error('Local identity provider is not configured')
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)))
  const state = base64url(crypto.getRandomValues(new Uint8Array(24)))
  const challenge = base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))))
  sessionStorage.setItem('sovereign_fleet_pkce_verifier', verifier)
  sessionStorage.setItem('sovereign_fleet_oidc_state', state)
  const target = new URL(`${issuer}/protocol/openid-connect/auth`)
  target.search = new URLSearchParams({
    client_id: clientId, redirect_uri: window.location.origin + '/', response_type: 'code',
    scope: 'openid', code_challenge: challenge, code_challenge_method: 'S256', state,
  }).toString()
  window.location.assign(target.toString())
}

export async function finishOidc(): Promise<string | null> {
  const issuer = configuredIssuer()
  if (!issuer) return null
  const url = new URL(window.location.href)
  const code = url.searchParams.get('code')
  if (!code) return null
  const state = url.searchParams.get('state')
  const expected = sessionStorage.getItem('sovereign_fleet_oidc_state')
  const verifier = sessionStorage.getItem('sovereign_fleet_pkce_verifier')
  sessionStorage.removeItem('sovereign_fleet_oidc_state')
  sessionStorage.removeItem('sovereign_fleet_pkce_verifier')
  window.history.replaceState({}, '', '/')
  if (!state || !expected || state !== expected || !verifier) throw new Error('Identity callback did not match this session')
  const response = await fetch(`${issuer}/protocol/openid-connect/token`, {
    method: 'POST', cache: 'no-store', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', client_id: clientId,
      code, redirect_uri: window.location.origin + '/', code_verifier: verifier }),
  })
  if (!response.ok) throw new Error('Local identity exchange failed')
  const result = await response.json() as { access_token?: string }
  if (!result.access_token) throw new Error('Local identity returned no access token')
  return result.access_token
}

export function endOidc(): void {
  const issuer = configuredIssuer()
  if (!issuer) return
  const target = new URL(`${issuer}/protocol/openid-connect/logout`)
  target.search = new URLSearchParams({ client_id: clientId, post_logout_redirect_uri: window.location.origin + '/' }).toString()
  window.location.assign(target.toString())
}
