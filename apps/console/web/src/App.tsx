import { useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import { api, stageDocument } from './api'
import type { AdminStatus, ChatResult, Citation, Identity, RelatedAlertEvidence, SecurityAnalysis, SecurityDetail, SecurityIncident, Source, SourcePreview, StagedUpload, ThreatIntelStatus, Turn } from './api'
import { beginOidc, endOidc, finishOidc, oidcEnabled } from './oidc'

type View = 'chat' | 'documents' | 'security' | 'administration'
type LoginReply = { access_token: string }

const roleName: Record<string, string> = {
  captain: 'Captain',
  chief_engineer: 'Chief Engineer',
  chief_stewardess: 'Chief Stewardess',
  deckhand: 'Deckhand',
  avit_admin: 'AV/IT Administrator',
}

export default function App() {
  const [token, setToken] = useState<string | null>(null)
  const [identity, setIdentity] = useState<Identity | null>(null)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [view, setView] = useState<View>('chat')
  const [sources, setSources] = useState<Source[]>([])
  const [uploads, setUploads] = useState<StagedUpload[]>([])
  const [uploadsEnabled, setUploadsEnabled] = useState(false)
  const [uploadFile, setUploadFile] = useState<File | null>(null)
  const [uploadMessage, setUploadMessage] = useState('')
  const [models, setModels] = useState<string[]>([])
  const [selectedSources, setSelectedSources] = useState<string[]>([])
  const [workspace, setWorkspace] = useState('')
  const [mode, setMode] = useState<'documents' | 'general'>('documents')
  const [question, setQuestion] = useState('')
  const [conversationIds, setConversationIds] = useState<string[]>([])
  const [conversationId, setConversationId] = useState<string | null>(null)
  const [turns, setTurns] = useState<Turn[]>([])
  const [admin, setAdmin] = useState<AdminStatus | null>(null)
  const [incidents, setIncidents] = useState<SecurityIncident[]>([])
  const [threatIntel, setThreatIntel] = useState<ThreatIntelStatus | null>(null)
  const [securitySince, setSecuritySince] = useState('')
  const [securityUntil, setSecurityUntil] = useState('')
  const [incident, setIncident] = useState<SecurityDetail | null>(null)
  const [relatedAlerts, setRelatedAlerts] = useState<RelatedAlertEvidence | null>(null)
  const [relatedError, setRelatedError] = useState('')
  const [analysis, setAnalysis] = useState<SecurityAnalysis | null>(null)
  const [filter, setFilter] = useState('')
  const [preview, setPreview] = useState<{ bearer: string; source: SourcePreview } | null>(null)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!oidcEnabled()) return
    void finishOidc().then((bearer) => bearer ? loadSession(bearer) : undefined)
      .catch((cause) => setError(cause instanceof Error ? cause.message : 'Local sign-in failed'))
  }, [])

  useEffect(() => {
    if (identity) document.getElementById('view-heading')?.focus()
  }, [identity, view])

  const collections = useMemo(() => [...new Set(sources.map((source) => source.collection))].sort(), [sources])
  const visibleSources = useMemo(() => sources.filter((source) =>
    (!workspace || source.collection === workspace) &&
    `${source.document_id} ${source.collection}`.toLowerCase().includes(filter.toLowerCase()),
  ), [sources, workspace, filter])

  async function loadSession(bearer: string) {
      const [me, files, modelList, sessions, staged] = await Promise.all([
        api<Identity>('/me', bearer),
        api<{ sources: Source[] }>('/sources', bearer),
        api<{ models: string[] }>('/models', bearer),
        api<{ conversation_ids: string[] }>('/conversations', bearer),
        api<{ uploads: StagedUpload[]; enabled: boolean }>('/documents/staged', bearer),
      ])
      setToken(bearer)
      setIdentity(me)
      setPreview(null)
      setSources(files.sources)
      setUploads(staged.uploads)
      setUploadsEnabled(staged.enabled)
      setModels(modelList.models)
      setConversationIds(sessions.conversation_ids)
      setPassword('')
  }

  async function signIn(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setPending(true)
    setError('')
    try {
      const login = await api<LoginReply>('/login', null, {
        method: 'POST', body: JSON.stringify({ user_id: username.trim(), password }),
      })
      await loadSession(login.access_token)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Sign-in failed')
    } finally {
      setPending(false)
    }
  }

  async function signOut() {
    if (token) {
      try { await api('/logout', token, { method: 'POST' }) } catch { /* clear client state */ }
    }
    setToken(null)
    setIdentity(null)
    setConversationId(null)
    setConversationIds([])
    setTurns([])
    setSources([])
    setUploads([])
    setUploadFile(null)
    setUploadMessage('')
    setSelectedSources([])
    setAdmin(null)
    setIncidents([])
    setThreatIntel(null)
    setSecuritySince('')
    setSecurityUntil('')
    setIncident(null)
    setRelatedAlerts(null)
    setRelatedError('')
    setAnalysis(null)
    setPreview(null)
    setError('')
    if (oidcEnabled()) endOidc()
  }

  async function openConversation(id: string) {
    if (!token) return
    setError('')
    try {
      const result = await api<{ conversation_id: string; turns: Turn[] }>(`/conversations/${encodeURIComponent(id)}`, token)
      setConversationId(result.conversation_id)
      setTurns(result.turns)
      setView('chat')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'History unavailable')
    }
  }

  function newConversation() {
    setConversationId(null)
    setTurns([])
    setView('chat')
    setError('')
    setPreview(null)
  }

  async function openCitation(citation: Citation) {
    if (!token) return
    setError('')
    setPreview(null)
    try {
      const result = await api<SourcePreview>(
        `/sources/${encodeURIComponent(citation.document_id)}/preview?ordinal=${citation.ordinal ?? 0}`, token,
      )
      if (result.sha256 !== citation.sha256 || result.version !== citation.version) {
        throw new Error('The cited source has changed. Ask again for a current answer.')
      }
      setPreview({ bearer: token, source: result })
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Source preview unavailable')
    }
  }

  async function openAdmin() {
    if (!token) return
    setView('administration')
    setError('')
    try { setAdmin(await api<AdminStatus>('/admin/status', token)) }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Administration unavailable') }
  }

  async function openSecurity() {
    if (!token || identity?.role !== 'avit_admin') return
    setView('security')
    setError('')
    setIncident(null)
    setAnalysis(null)
    setIncidents([])
    setThreatIntel(null)
    if (Boolean(securitySince) !== Boolean(securityUntil)) {
      setError('Enter both start and end times, or clear both to view recent alerts.')
      return
    }
    try {
      const range = securitySince && securityUntil
        ? `?since=${encodeURIComponent(new Date(securitySince).toISOString())}&until=${encodeURIComponent(new Date(securityUntil).toISOString())}`
        : ''
      setIncidents((await api<{ incidents: SecurityIncident[] }>(`/security/incidents${range}`, token)).incidents)
    }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Security alerts unavailable') }
    try { setThreatIntel(await api<ThreatIntelStatus>('/security/threat-intel', token)) }
    catch { setThreatIntel({ status: 'unavailable', warning: 'Offline threat snapshot could not be verified.' }) }
  }

  async function openIncident(id: string) {
    if (!token) return
    setError('')
    setAnalysis(null)
    setRelatedAlerts(null)
    setRelatedError('')
    try {
      const path = `/security/incidents/${encodeURIComponent(id)}`
      setIncident(await api<SecurityDetail>(path, token))
      try { setRelatedAlerts(await api<RelatedAlertEvidence>(`${path}/related`, token)) }
      catch (cause) { setRelatedError(cause instanceof Error ? cause.message : 'Related alert evidence unavailable') }
    }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Incident unavailable') }
  }

  async function explainIncident() {
    if (!token || !incident || pending) return
    setPending(true)
    setError('')
    try { setAnalysis(await api<SecurityAnalysis>(`/security/incidents/${encodeURIComponent(incident.incident_id)}/explain`, token, { method: 'POST' })) }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Analysis unavailable') }
    finally { setPending(false) }
  }

  async function sendQuestion(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!token || !question.trim() || pending) return
    setPending(true)
    setError('')
    try {
      const result = await api<ChatResult>('/chat', token, {
        method: 'POST',
        body: JSON.stringify({
          message: question.trim(), mode, model: models[0],
          conversation_id: conversationId,
          workspace: mode === 'documents' ? workspace || null : null,
          selected_documents: mode === 'documents' ? selectedSources : [],
        }),
      })
      setConversationId(result.conversation_id)
      setConversationIds((current) => current.includes(result.conversation_id)
        ? current : [result.conversation_id, ...current])
      setTurns((current) => [...current, result])
      setQuestion('')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Local model unavailable')
    } finally {
      setPending(false)
    }
  }

  function toggleSource(id: string) {
    setSelectedSources((current) => {
      if (current.includes(id)) return current.filter((item) => item !== id)
      if (current.length >= 5) {
        setError('Select at most five sources')
        return current
      }
      setError('')
      return [...current, id]
    })
  }

  if (!token || !identity) return (
    <div className="min-h-screen bg-[#eef2f1] px-4 py-10 text-[#173045] sm:py-20">
      <main className="mx-auto grid max-w-5xl overflow-hidden rounded-3xl bg-white shadow-2xl lg:grid-cols-2">
        <section className="flex min-h-80 flex-col justify-between bg-[#102b3d] p-10 text-white sm:p-14">
          <div className="text-sm font-bold tracking-[.3em] text-[#9bc2be]">SOVEREIGN</div>
          <div>
            <div className="mb-5 inline-flex rounded-full border border-[#668783] px-3 py-1 text-xs tracking-widest">PRIVATE VESSEL AI</div>
            <h1 className="max-w-sm text-4xl font-semibold leading-tight sm:text-5xl">Knowledge stays on board.</h1>
            <p className="mt-5 max-w-sm text-[#c4d3d3]">A local workspace for crew questions and approved vessel documents.</p>
          </div>
          <p className="text-sm text-[#9bb1b8]">Synthetic development lab · No vessel data</p>
        </section>
        <section className="flex flex-col justify-center p-10 sm:p-14">
          <div className="mb-8 text-xs font-semibold uppercase tracking-[.2em] text-[#895534]">Crew access</div>
          <h2 className="text-3xl font-semibold">Sign in</h2>
          <p className="mt-2 text-sm text-[#607583]">{oidcEnabled() ? 'Use your named account with the local identity provider.' : 'Use a named synthetic lab account and the local lab passphrase.'}</p>
          {oidcEnabled() ? <button className="primary-button mt-8 w-full" onClick={() => void beginOidc().catch((cause) => setError(cause instanceof Error ? cause.message : 'Sign-in unavailable'))}>Continue to local sign-in</button> : <form onSubmit={signIn} className="mt-8 space-y-5">
            <label className="block text-sm font-medium">User ID
              <input className="field mt-2" value={username} onChange={(event) => setUsername(event.target.value)}
                autoComplete="username" required placeholder="lab-chief_engineer-1" />
            </label>
            <label className="block text-sm font-medium">Lab passphrase
              <input className="field mt-2" type="password" value={password} onChange={(event) => setPassword(event.target.value)}
                autoComplete="current-password" required placeholder="Enter passphrase" />
            </label>
            {error && <p role="alert" className="rounded-xl bg-red-50 p-3 text-sm text-red-800">{error}</p>}
            <button className="primary-button w-full" disabled={pending}>{pending ? 'Connecting…' : 'Enter workspace'}</button>
          </form>}
          {error && oidcEnabled() && <p role="alert" className="mt-4 rounded-xl bg-red-50 p-3 text-sm text-red-800">{error}</p>}
          <p className="mt-8 text-xs leading-5 text-[#778b96]">Synthetic lab only. Vessel identity and security review require separate approval.</p>
        </section>
      </main>
    </div>
  )

  return (
    <div className="min-h-screen bg-[#f5f7f5] text-[#173045] lg:flex">
      <aside className="flex w-full flex-col bg-[#102b3d] p-5 text-white lg:min-h-screen lg:w-72 lg:p-7">
        <div className="text-lg font-bold tracking-[.25em]">SOVEREIGN</div>
        <div className="mt-1 text-xs uppercase tracking-widest text-[#9bb1b8]">Console · Synthetic Lab</div>
        <nav aria-label="Workspace" className="mt-9 flex flex-wrap gap-2 lg:flex-col">
          <button className={`nav-button ${view === 'chat' ? 'nav-active' : ''}`} aria-current={view === 'chat' ? 'page' : undefined} onClick={() => setView('chat')}>AI Chat</button>
          <button className={`nav-button ${view === 'documents' ? 'nav-active' : ''}`} aria-current={view === 'documents' ? 'page' : undefined} onClick={() => setView('documents')}>Documents</button>
          {identity.role === 'avit_admin' && <button className={`nav-button ${view === 'security' ? 'nav-active' : ''}`}
            aria-current={view === 'security' ? 'page' : undefined} onClick={() => void openSecurity()}>Security</button>}
          {identity.role === 'avit_admin' && <button className={`nav-button ${view === 'administration' ? 'nav-active' : ''}`}
            aria-current={view === 'administration' ? 'page' : undefined} onClick={openAdmin}>Administration</button>}
        </nav>
        <div className="mt-4 lg:hidden">
          <button className="secondary-button w-full" onClick={newConversation}>+ New conversation</button>
          {conversationIds.length > 0 && <details className="mt-3">
            <summary className="cursor-pointer py-2 text-sm font-semibold">Conversations ({conversationIds.length})</summary>
            <div className="mt-2 max-h-48 space-y-1 overflow-y-auto">
              {conversationIds.map((id, index) => <button key={id} className="nav-button block w-full text-left text-sm" onClick={() => void openConversation(id)}>
                Conversation {conversationIds.length - index}
              </button>)}
            </div>
          </details>}
        </div>
        <div className="mt-9 hidden lg:block">
          <div className="mb-3 text-xs uppercase tracking-widest text-[#9bb1b8]">Conversations</div>
          <button className="secondary-button w-full" onClick={newConversation}>+ New conversation</button>
          <div className="mt-3 space-y-1">
            {conversationIds.map((id, index) => <button key={id} className="nav-button w-full text-left text-sm" onClick={() => void openConversation(id)}>
              Conversation {conversationIds.length - index}
            </button>)}
          </div>
        </div>
        <div className="mt-auto hidden border-t border-[#315064] pt-6 lg:block">
          <div className="font-semibold">{roleName[identity.role] || identity.role}</div>
          <div className="mb-4 text-xs text-[#9bb1b8]">{identity.id}</div>
          <button className="text-sm text-[#b7d0cc] underline" onClick={signOut}>Sign out</button>
        </div>
      </aside>

      <main className="mx-auto w-full max-w-6xl px-5 py-7 sm:px-10 lg:py-10">
        <header className="mb-8 flex flex-wrap items-start justify-between gap-4 border-b border-[#dce5e5] pb-6">
          <div>
            <div className="mb-2 text-xs font-semibold uppercase tracking-[.2em] text-[#895534]">{roleName[identity.role] || identity.role} workspace</div>
            <h1 id="view-heading" tabIndex={-1} className="text-3xl font-semibold outline-none sm:text-4xl">{view === 'chat' ? 'Private Vessel Assistant' : view === 'documents' ? 'Approved documents' : view === 'security' ? 'Security alerts' : 'Lab administration'}</h1>
            <p className="mt-2 text-sm text-[#637985]">Local AI · Synthetic documents only · Read-only tools</p>
          </div>
          <button className="secondary-button lg:hidden" onClick={signOut}>Sign out</button>
        </header>

        {error && <div role="alert" className="mb-5 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-800">{error}</div>}

        {view === 'chat' && <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_280px]">
          <section className="flex min-h-[600px] flex-col rounded-2xl border border-[#e0e7e5] bg-white shadow-sm">
            <div className="flex flex-wrap items-center gap-3 border-b border-[#e8eeee] p-5">
              <label className="text-xs font-semibold uppercase tracking-wider text-[#5d7380]">Mode
                <select className="field mt-1 w-auto min-w-44" value={mode} onChange={(event) => setMode(event.target.value as 'documents' | 'general')}>
                  <option value="documents">Vessel documents</option><option value="general">General chat</option>
                </select>
              </label>
              <label className="text-xs font-semibold uppercase tracking-wider text-[#5d7380]">Department
                <select className="field mt-1 w-auto min-w-44" value={workspace} disabled={mode === 'general'} onChange={(event) => setWorkspace(event.target.value)}>
                  <option value="">All permitted</option>{collections.map((collection) => <option key={collection} value={collection}>{collection}</option>)}
                </select>
              </label>
              <span className="ml-auto self-end rounded-full bg-[#e7f1ed] px-3 py-2 text-xs font-medium text-[#2e6d5a]">{models[0] || 'Local model'}</span>
            </div>
            <div className="flex-1 space-y-6 p-5 sm:p-7" aria-label="Conversation transcript">
              {turns.length === 0 && <div className="mx-auto max-w-md py-20 text-center">
                <div className="mx-auto mb-5 flex h-14 w-14 items-center justify-center rounded-2xl bg-[#e7f1ed] text-2xl text-[#2e6d5a]">✦</div>
                <h2 className="text-xl font-semibold">Ask a question</h2>
                <p className="mt-3 text-sm leading-6 text-[#5d7380]">Try “generator inspection” as a permitted engineer. Answers based on documents include source references.</p>
              </div>}
              {turns.map((turn, index) => <article key={index} className="space-y-3">
                <div className="ml-auto max-w-[85%] rounded-2xl rounded-tr-sm bg-[#173b51] px-5 py-3 text-sm text-white">{turn.message}</div>
                <div className="max-w-[95%] rounded-2xl rounded-tl-sm bg-[#f1f5f3] px-5 py-4">
                  <p className="whitespace-pre-wrap text-sm leading-7">{turn.answer}</p>
                  {turn.citations.length > 0 && <div className="mt-4 border-t border-[#d8e3df] pt-3">
                    <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-[#617b77]">Sources</div>
                    <div className="flex flex-wrap gap-2">{turn.citations.map((citation) =>
                      <button key={`${citation.document_id}-${citation.ordinal ?? 0}`} type="button" onClick={() => void openCitation(citation)}
                        aria-label={`Preview source ${citation.document_id}, version ${citation.version}`}
                        className="rounded-lg bg-white px-3 py-2 text-xs font-medium text-[#285e56] underline">
                        {citation.document_id} · v{citation.version} · {citation.collection}
                      </button>)}</div>
                  </div>}
                </div>
              </article>)}
              {preview?.bearer === token && <section aria-label={`Source preview ${preview.source.document_id}`} className="rounded-xl border border-[#b9d3cb] bg-[#f6faf8] p-4">
                <div className="flex items-center justify-between gap-3">
                  <h2 className="font-semibold">{preview.source.document_id} · v{preview.source.version} · passage {preview.source.ordinal + 1}</h2>
                  <button type="button" className="text-sm font-semibold underline" onClick={() => setPreview(null)}>Close preview</button>
                </div>
                <p className="mt-3 whitespace-pre-wrap text-sm leading-6">{preview.source.excerpt}</p>
              </section>}
              {pending && <p role="status" className="text-sm text-[#607583]">The local model is preparing an answer…</p>}
            </div>
            <form onSubmit={sendQuestion} className="border-t border-[#e8eeee] p-5">
              {selectedSources.length > 0 && mode === 'documents' && <p className="mb-3 text-xs text-[#53766d]">Selected: {selectedSources.join(', ')}</p>}
              <label className="sr-only" htmlFor="question">Ask a question</label>
              <textarea id="question" className="field min-h-24 resize-y" maxLength={2000} value={question}
                onChange={(event) => setQuestion(event.target.value)} placeholder="Ask about approved vessel documents…" />
              <div className="mt-3 flex items-center justify-between gap-3">
                <span className="text-xs text-[#607583]">Answers may be uncertain. Check the cited source.</span>
                <button className="primary-button" disabled={pending || !question.trim()}>{pending ? 'Working…' : 'Send question'}</button>
              </div>
            </form>
          </section>
          <aside className="rounded-2xl border border-[#e0e7e5] bg-white p-5 shadow-sm">
            <h2 className="font-semibold">Current scope</h2>
            <p className="mt-2 text-sm leading-6 text-[#5d7380]">Search is limited to documents allowed for your lab role.</p>
            <div className="mt-5 text-3xl font-semibold text-[#2e6d5a]">{sources.length}</div>
            <div className="text-xs text-[#5d7380]">permitted source records</div>
            <button className="mt-6 text-sm font-semibold text-[#2e6d5a] underline" onClick={() => setView('documents')}>Choose source files</button>
            <div className="mt-8 rounded-xl bg-[#f3f6f4] p-4 text-xs leading-5 text-[#607583]">A missing source yields a clear no-answer. No equipment control tools are available in this lab.</div>
          </aside>
        </div>}

        {view === 'documents' && <section className="rounded-2xl border border-[#e0e7e5] bg-white p-5 shadow-sm sm:p-7">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div><h2 className="text-xl font-semibold">Source library</h2><p className="mt-1 text-sm text-[#5d7380]">Select up to five documents to narrow the next chat question.</p></div>
            <button className="primary-button" onClick={() => setView('chat')}>Return to chat</button>
          </div>
          <div className="mt-6 grid gap-3 sm:grid-cols-2">
            <label className="text-sm font-medium">Search sources
              <input className="field mt-1" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Document ID or department" />
            </label>
            <label className="text-sm font-medium">Department
              <select className="field mt-1" value={workspace} onChange={(event) => setWorkspace(event.target.value)}>
                <option value="">All permitted</option>{collections.map((collection) => <option key={collection} value={collection}>{collection}</option>)}
              </select>
            </label>
          </div>
          <div className="mt-6 grid max-h-[560px] gap-2 overflow-y-auto sm:grid-cols-2">
            {visibleSources.map((source) => <label key={source.document_id} className="flex cursor-pointer items-center gap-3 rounded-xl border border-[#e3ebea] p-4 hover:bg-[#f7faf8]">
              <input type="checkbox" checked={selectedSources.includes(source.document_id)} onChange={() => toggleSource(source.document_id)}
                className="h-4 w-4 accent-[#2e6d5a]" />
              <span><strong className="block text-sm">{source.document_id}</strong><span className="text-xs text-[#5d7380]">{source.collection} · version {source.version}</span></span>
            </label>)}
            {visibleSources.length === 0 && <p className="text-sm text-[#5d7380]">No permitted sources match this filter.</p>}
          </div>
          {uploadsEnabled && <div className="mt-8 border-t border-[#e0e7e5] pt-6">
            <h3 className="text-lg font-semibold">Submit a document for review</h3>
            <p className="mt-1 text-sm text-[#5d7380]">PDF, DOCX, XLSX or TXT, up to 8 MB. Submitted files stay private and unavailable to AI search until separately approved.</p>
            <form className="mt-4 flex flex-wrap items-end gap-3" onSubmit={(event) => { event.preventDefault(); if (!token || !uploadFile) return; setPending(true); setUploadMessage(''); void stageDocument(token, uploadFile).then((item) => { setUploads((items) => [item, ...items]); setUploadFile(null); setUploadMessage('Submitted for review. This file is not searchable.'); }).catch((cause) => setUploadMessage(cause instanceof Error ? cause.message : 'Upload failed')).finally(() => setPending(false)) }}>
              <label className="text-sm font-medium">Document file<input className="field mt-1" type="file" accept=".pdf,.docx,.xlsx,.txt" onChange={(event) => setUploadFile(event.target.files?.[0] ?? null)} /></label>
              <button className="primary-button" type="submit" disabled={!uploadFile || pending}>Submit</button>
            </form>
            {uploadMessage && <p role="status" className="mt-3 text-sm">{uploadMessage}</p>}
            {uploads.length > 0 && <ul className="mt-4 space-y-2 text-sm">{uploads.map((item) => <li key={item.id} className="rounded-xl border border-[#e3ebea] p-3">{item.filename} · pending review · {Math.ceil(item.size / 1024)} KB</li>)}</ul>}
          </div>}
        </section>}

        {view === 'security' && identity.role === 'avit_admin' && <section className="rounded-2xl border border-[#e0e7e5] bg-white p-7 shadow-sm">
          <h2 className="text-xl font-semibold">Read-only incident review</h2>
          <p className="mt-2 text-sm text-[#5d7380]">Synthetic alert evidence. Verify every finding in the independent Wazuh store before acting.</p>
          {threatIntel && <div className="mt-4 rounded-xl border border-[#dce5e5] p-4 text-sm" role="status">
            <strong>Offline threat intelligence: {threatIntel.status}</strong>
            {threatIntel.feed_id && <p className="mt-1">{threatIntel.feed_id} · {threatIntel.publisher} · issued {threatIntel.issued_at} · {threatIntel.indicator_count} indicators · age {threatIntel.age_hours} hours</p>}
            {threatIntel.warning && <p className="mt-1 font-medium text-[#8b421c]">{threatIntel.warning}</p>}
            <p className="mt-1 text-xs text-[#5d7380]">This signed offline snapshot is advisory and does not provide live coverage.</p>
          </div>}
          <div className="mt-4 flex flex-wrap items-end gap-3">
            <label className="text-sm">From<input className="field mt-1" type="datetime-local" value={securitySince} onChange={(event) => setSecuritySince(event.target.value)} /></label>
            <label className="text-sm">To<input className="field mt-1" type="datetime-local" value={securityUntil} onChange={(event) => setSecurityUntil(event.target.value)} /></label>
            <button className="secondary-button" onClick={() => void openSecurity()}>Refresh alerts</button>
          </div>
          <p className="mt-2 text-xs text-[#5d7380]">Select a range of at most seven days, or leave both times empty for recent alerts.</p>
          <div className="mt-5 grid gap-3">
            {incidents.map((item) => <button key={item.incident_id} className="rounded-xl border border-[#dce5e5] p-4 text-left hover:bg-[#f7faf8]" onClick={() => void openIncident(item.incident_id)}>
              <strong className="block text-sm">{item.summary}</strong><span className="text-xs text-[#5d7380]">{item.severity} · {item.timestamp} · {item.incident_id}</span>
            </button>)}
            {incidents.length === 0 && <p className="text-sm text-[#5d7380]">No alerts are available.</p>}
          </div>
          {incident && <article className="mt-7 rounded-xl bg-[#f3f6f4] p-5">
            <h3 className="font-semibold">{incident.incident_id}</h3>
            <p className="mt-2 text-sm">{incident.summary}</p>
            <p className="mt-2 text-sm">Source asset: {incident.event.asset?.hostname || incident.event.asset_status} · Owner: {incident.event.asset?.owner || 'unmapped'}</p>
            <p className="mt-2 text-sm">Related asset mapping: {incident.event.related_asset_status}</p>
            <h4 className="mt-5 text-sm font-semibold">Evidence</h4>
            <ul className="mt-2 list-disc pl-5 text-sm">{incident.evidence.map((entry) => <li key={`${entry.index_name}:${entry.index_id}`}>Wazuh alert {entry.event_id} · index {entry.index_name} / {entry.index_id} · {entry.timestamp} · rule {entry.rule_id} · {entry.location}</li>)}</ul>
            <h4 className="mt-5 text-sm font-semibold">Related alerts on the same mapped source</h4>
            {relatedError && <p className="mt-2 text-sm text-[#895534]">{relatedError}</p>}
            {relatedAlerts && <div className="mt-2 text-sm">
              {relatedAlerts.status === 'unresolved-source'
                ? <p>Source mapping is unresolved, so no related device is inferred.</p>
                : relatedAlerts.related.length === 0
                  ? <p>No same-source alert was found in the checked sample.</p>
                  : <ul className="list-disc pl-5">{relatedAlerts.related.map((item) => <li key={item.incident_id}>{item.summary} · {item.severity} · {item.timestamp} · {item.evidence[0].index_name} / {item.evidence[0].index_id}</li>)}</ul>}
              <p className="mt-2 text-xs text-[#5d7380]">{relatedAlerts.notice} {relatedAlerts.examined} alerts examined; at most 20 related alerts shown.</p>
            </div>}
            <h4 className="mt-5 text-sm font-semibold">Suggested checks</h4>
            <ul className="mt-2 list-disc pl-5 text-sm">{incident.suggested_checks.map((check) => <li key={check}>{check}</li>)}</ul>
            <p className="mt-4 text-xs text-[#5d7380]">{incident.confidence}</p>
            <button className="primary-button mt-5" disabled={pending} onClick={() => void explainIncident()}>{pending ? 'Analysing…' : 'Explain event'}</button>
            {analysis && <div className="mt-5 rounded-xl bg-white p-4" role="status"><h4 className="font-semibold">{analysis.method === 'local-model' ? 'AI explanation' : 'Evidence summary'}</h4><p className="mt-2 whitespace-pre-wrap text-sm">{analysis.analysis}</p><h5 className="mt-3 text-sm font-semibold">Evidence supplied</h5><ul className="mt-1 list-disc pl-5 text-xs">{analysis.evidence.map((entry) => <li key={`${entry.index_name}:${entry.index_id}`}>{entry.event_id} · {entry.index_name} / {entry.index_id} · {entry.timestamp}</li>)}</ul><p className="mt-3 text-xs text-[#895534]">{analysis.notice}</p></div>}
          </article>}
        </section>}

        {view === 'administration' && <section className="rounded-2xl border border-[#e0e7e5] bg-white p-7 shadow-sm">
          <h2 className="text-xl font-semibold">Read-only lab status</h2>
          <p className="mt-2 text-sm text-[#5d7380]">This view reports the synthetic Core configuration. Vessel administration is not enabled.</p>
          {admin && <dl className="mt-7 grid gap-4 sm:grid-cols-2">
            <div className="status-card"><dt>Operating mode</dt><dd>{admin.mode}</dd></div>
            <div className="status-card"><dt>Identity</dt><dd>{admin.identity}</dd></div>
            <div className="status-card"><dt>Local model</dt><dd>{admin.model}</dd></div>
            <div className="status-card"><dt>Read-only tools</dt><dd>{admin.read_only_tools.join(', ') || 'None'}</dd></div>
            <div className="status-card"><dt>Write tools</dt><dd>{admin.write_tools.length}</dd></div>
          </dl>}
        </section>}
      </main>
    </div>
  )
}
