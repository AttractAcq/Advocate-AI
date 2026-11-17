import { createRoot } from 'react-dom/client'
import App from './App'
import { loadRuntimeConfig } from './runtime-config'
import './style.css'

const root = document.getElementById('root')!
void loadRuntimeConfig().then(() => {
  createRoot(root).render(<App />)
}).catch(() => {
  root.textContent = 'Fleet configuration is unavailable. Contact the company administrator.'
  root.setAttribute('role', 'alert')
})
