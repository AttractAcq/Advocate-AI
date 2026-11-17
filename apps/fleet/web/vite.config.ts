import { defineConfig } from 'vite'
import { env } from 'node:process'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss(), {
    name: 'sovereign-dev-fleet-config',
    configureServer(server) {
      server.middlewares.use((request, response, next) => {
        if (request.method !== 'GET' || request.url !== '/fleet-config.json') return next()
        response.setHeader('Content-Type', 'application/json')
        response.setHeader('Cache-Control', 'no-store')
        response.end(JSON.stringify({ schema: 1, oidc_issuer: env.VITE_FLEET_OIDC_ISSUER || null }))
      })
    },
  }],
  server: {
    host: '127.0.0.1',
    port: 18801,
    strictPort: true,
    proxy: { '/api/fleet': 'http://127.0.0.1:18800' },
  },
})
