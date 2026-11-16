import { defineConfig } from 'vite'
import { env } from 'node:process'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss(), {
    name: 'sovereign-dev-console-config',
    configureServer(server) {
      server.middlewares.use((request, response, next) => {
        if (request.method !== 'GET' || request.url !== '/console-config.json') return next()
        response.setHeader('Content-Type', 'application/json')
        response.setHeader('Cache-Control', 'no-store')
        response.end(JSON.stringify({ schema: 1, oidc_issuer: env.VITE_OIDC_ISSUER || null }))
      })
    },
  }],
  server: {
    host: '127.0.0.1',
    port: 18101,
    strictPort: true,
    proxy: { '/api': 'http://127.0.0.1:18100' },
  },
})
