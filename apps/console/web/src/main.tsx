import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import { loadRuntimeConfig } from './runtime-config'
import './style.css'

const root = document.getElementById('root')!
void loadRuntimeConfig().then(() => {
  createRoot(root).render(<React.StrictMode><App /></React.StrictMode>)
}).catch(() => {
  root.textContent = 'Console configuration is unavailable. Contact the AV/IT administrator.'
  root.setAttribute('role', 'alert')
})
