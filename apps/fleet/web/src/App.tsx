import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { fleetApi } from './api'
import type { FleetRow } from './api'
import { signedReceiptEnvelope } from './receipt'
import type { ReceiptInput } from './receipt'

type Section = 'overview' | 'customers' | 'releases' | 'deployments' |
  'licences' | 'tickets' | 'maintenance' | 'receipts' | 'audit'
type Field = { name: string; label: string; type?: 'date'; options?: string[] }

const sections: { id: Section; label: string; description: string; endpoint?: string;
  columns?: string[]; fields?: Field[] }[] = [
  { id: 'overview', label: 'Overview', description: 'Company-side installation metadata' },
  { id: 'customers', label: 'Customers', description: 'Coded customer accounts',
    endpoint: 'customers', columns: ['code', 'category'], fields: [
      { name: 'code', label: 'Customer code' },
      { name: 'category', label: 'Category', options: ['owner_manager', 'charter_operator', 'service_partner'] },
    ] },
  { id: 'releases', label: 'Releases', description: 'Signed product candidates and approval state',
    endpoint: 'releases', columns: ['code', 'version', 'status', 'manifest_sha256', 'signing_key_id'] },
  { id: 'deployments', label: 'Deployments', description: 'Planned and installed vessel records',
    endpoint: 'deployments', columns: ['code', 'customer_code', 'release_code', 'hardware_profile', 'status'],
    fields: [
      { name: 'code', label: 'Vessel code' }, { name: 'customer_code', label: 'Customer code' },
      { name: 'release_code', label: 'Approved release code' },
      { name: 'hardware_profile', label: 'Hardware profile', options: ['reference_gpu', 'pilot_gpu', 'other_approved'] },
      { name: 'status', label: 'Status', options: ['planned', 'lab', 'pilot', 'active', 'retired'] },
    ] },
  { id: 'licences', label: 'Licences', description: 'Customer and vessel entitlements',
    endpoint: 'licences', columns: ['code', 'customer_code', 'vessel_code', 'tier', 'valid_from', 'valid_until', 'status'],
    fields: [
      { name: 'code', label: 'Licence code' }, { name: 'customer_code', label: 'Customer code' },
      { name: 'vessel_code', label: 'Vessel code' },
      { name: 'tier', label: 'Tier', options: ['pilot', 'standard', 'fleet'] },
      { name: 'valid_from', label: 'Valid from', type: 'date' },
      { name: 'valid_until', label: 'Valid until', type: 'date' },
      { name: 'status', label: 'Status', options: ['pending', 'active', 'suspended', 'expired'] },
    ] },
  { id: 'tickets', label: 'Support', description: 'Coded support work, without vessel content',
    endpoint: 'tickets', columns: ['code', 'vessel_code', 'category', 'priority', 'status'], fields: [
      { name: 'code', label: 'Ticket code' }, { name: 'vessel_code', label: 'Vessel code' },
      { name: 'category', label: 'Category', options: ['installation', 'update', 'recovery', 'access', 'hardware'] },
      { name: 'priority', label: 'Priority', options: ['p1', 'p2', 'p3', 'p4'] },
      { name: 'status', label: 'Status', options: ['open', 'triaged', 'waiting', 'resolved'] },
    ] },
  { id: 'maintenance', label: 'Maintenance', description: 'Scheduled product operations',
    endpoint: 'maintenance', columns: ['code', 'vessel_code', 'kind', 'due_on', 'engineer_code', 'status'],
    fields: [
      { name: 'code', label: 'Maintenance code' }, { name: 'vessel_code', label: 'Vessel code' },
      { name: 'kind', label: 'Kind', options: ['backup_rehearsal', 'permission_review', 'offline_update', 'hardware_check'] },
      { name: 'due_on', label: 'Due on', type: 'date' },
      { name: 'engineer_code', label: 'Engineer code' },
      { name: 'status', label: 'Status', options: ['planned', 'completed', 'deferred'] },
    ] },
  { id: 'receipts', label: 'Offline receipts', description: 'Signed import results and health metadata',
    endpoint: 'import/deployment-receipts',
    columns: ['code', 'vessel_code', 'release_code', 'observed_on', 'health', 'source'] },
  { id: 'audit', label: 'Audit', description: 'Record changes and digest-bound issuer events',
    endpoint: 'audit', columns: ['seq', 'at', 'action', 'kind', 'code', 'digest', 'chain_hash'] },
]

const nextStatuses: Partial<Record<Section, Record<string, string[]>>> = {
  releases: { candidate: ['approved'], approved: ['retired'] },
  licences: { pending: ['active', 'expired'], active: ['suspended', 'expired'],
    suspended: ['active', 'expired'] },
  tickets: { open: ['triaged'], triaged: ['waiting', 'resolved'],
    waiting: ['triaged', 'resolved'] },
  maintenance: { planned: ['completed', 'deferred'], deferred: ['planned'] },
}

const emptyReceipt: ReceiptInput = {
  code: '', vessel_code: '', release_code: '', observed_on: '',
  health: 'healthy', key_id: '', signature: '',
}

function display(value: string | number | null | undefined, column: string) {
  if (value === null || value === undefined) return '—'
  if (column.endsWith('sha256') || column.endsWith('key_id') || column === 'digest' || column === 'chain_hash') {
    return `${String(value).slice(0, 12)}…`
  }
  return String(value).replaceAll('_', ' ')
}

export default function App() {
  const [token, setToken] = useState('')
  const [entryToken, setEntryToken] = useState('')
  const [section, setSection] = useState<Section>('overview')
  const [rows, setRows] = useState<Record<string, FleetRow[]>>({})
  const [hasMore, setHasMore] = useState<Record<string, boolean>>({})
  const [form, setForm] = useState<Record<string, string>>({})
  const [receiptForm, setReceiptForm] = useState<ReceiptInput>(emptyReceipt)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  async function refresh(activeToken: string) {
    setLoading(true)
    setError('')
    try {
      const entries = await Promise.all(sections.filter((item) => item.endpoint).map(async (item) =>
        [item.id, await fleetApi<FleetRow[]>(`/api/fleet/${item.endpoint}`, activeToken)] as const))
      setRows(Object.fromEntries(entries))
      setHasMore(Object.fromEntries(entries.map(([id, values]) => [id, values.length === 100])))
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : 'Fleet data is unavailable'
      if (message === 'Fleet lab token was rejected') {
        setToken('')
        setRows({})
        setHasMore({})
      }
      setError(message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { if (token) void refresh(token) }, [token])

  function signIn(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (entryToken.trim().length < 32) {
      setError('Enter the configured Fleet lab token.')
      return
    }
    setToken(entryToken.trim())
    setEntryToken('')
    setError('')
  }

  function signOut() {
    setToken('')
    setEntryToken('')
    setRows({})
    setHasMore({})
    setForm({})
    setReceiptForm(emptyReceipt)
    setSection('overview')
    setNotice('')
    setError('')
  }

  async function createRecord(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const current = sections.find((item) => item.id === section)
    if (!token || !current?.endpoint || !current.fields) return
    setLoading(true)
    setError('')
    setNotice('')
    try {
      const payload = Object.fromEntries(current.fields.map((field) =>
        [field.name, (form[field.name] || field.options?.[0] || '').trim()]))
      await fleetApi<FleetRow>(`/api/fleet/${current.endpoint}`, token,
        { method: 'POST', body: JSON.stringify(payload) })
      setForm({})
      setNotice(`${current.label} record created.`)
      await refresh(token)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Record could not be created')
    } finally {
      setLoading(false)
    }
  }

  async function changeStatus(code: string, status: string) {
    if (!token) return
    setLoading(true)
    setError('')
    setNotice('')
    try {
      await fleetApi<FleetRow>(`/api/fleet/${section}/${encodeURIComponent(code)}/status`, token,
        { method: 'PATCH', body: JSON.stringify({ status }) })
      setNotice(`${code} moved to ${status.replaceAll('_', ' ')}.`)
      await refresh(token)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Status could not be changed')
    } finally {
      setLoading(false)
    }
  }

  async function importReceipt(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!token) return
    setLoading(true)
    setError('')
    setNotice('')
    try {
      await fleetApi<FleetRow>('/api/fleet/import/deployment-receipts', token,
        { method: 'POST', body: JSON.stringify(signedReceiptEnvelope(receiptForm)) })
      setReceiptForm(emptyReceipt)
      setNotice('Signed deployment receipt imported.')
      await refresh(token)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Signed receipt was rejected')
    } finally {
      setLoading(false)
    }
  }

  async function loadMore() {
    if (!token || !current.endpoint || !visible.length) return
    const last = visible[visible.length - 1]
    const cursor = section === 'audit' ? last.seq : last.code
    if (cursor === null || cursor === undefined) return
    setLoading(true)
    setError('')
    try {
      const page = await fleetApi<FleetRow[]>(
        `/api/fleet/${current.endpoint}?limit=100&after=${encodeURIComponent(String(cursor))}`, token)
      setRows((existing) => ({ ...existing, [section]: [...(existing[section] || []), ...page] }))
      setHasMore((existing) => ({ ...existing, [section]: page.length === 100 }))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'More Fleet records are unavailable')
    } finally {
      setLoading(false)
    }
  }

  const current = sections.find((item) => item.id === section)!
  const visible = rows[section] || []

  if (!token) return (
    <main className="signin-shell">
      <div className="signin-panel">
        <div className="brand-mark">S<span>◇</span></div>
        <p className="eyebrow">Sovereign · company workspace</p>
        <h1>Fleet operations</h1>
        <p className="muted">Synthetic local portal for coded company metadata. Vessel documents, prompts, embeddings and security logs are excluded.</p>
        <form onSubmit={signIn}>
          <label htmlFor="lab-token">Fleet lab token</label>
          <input id="lab-token" type="password" autoComplete="off" value={entryToken}
            onChange={(event) => setEntryToken(event.target.value)} required minLength={32} />
          <button type="submit" className="primary">Open workspace</button>
        </form>
        {error && <p role="alert" className="error">{error}</p>}
        <p className="lab-note">The token stays in this browser tab’s memory. This local sign-in is not production identity.</p>
      </div>
    </main>
  )

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">S<span>◇</span></span><span><strong>Sovereign</strong><small>FLEET · LAB</small></span></div>
        <nav aria-label="Fleet sections">
          {sections.map((item) => <button key={item.id} type="button"
            className={section === item.id ? 'nav-link active' : 'nav-link'}
            aria-current={section === item.id ? 'page' : undefined}
            onClick={() => { setSection(item.id); setForm({}); setError(''); setNotice('') }}>
            {item.label}
          </button>)}
        </nav>
        <div className="sidebar-bottom"><p>Company-side metadata only</p><button type="button" onClick={signOut}>Sign out</button></div>
      </aside>
      <main className="content">
        <header className="topbar"><span>PRIVATE OPERATIONS · SYNTHETIC LAB</span>
          <button type="button" onClick={() => void refresh(token)} disabled={loading}>Refresh records</button></header>
        <div className="page">
          <div className="page-heading"><p className="eyebrow">Company management</p><h1>{current.label}</h1><p>{current.description}</p></div>
          {error && <p role="alert" className="error">{error}</p>}
          {notice && <p role="status" className="notice">{notice}</p>}
          {loading && <p role="status" className="muted">Updating Fleet records…</p>}
          {section === 'overview' ? (
            <>
              <div className="metrics">{sections.filter((item) => item.endpoint && item.id !== 'audit').map((item) =>
                <button type="button" className="metric" key={item.id} onClick={() => setSection(item.id)}>
                  <span>{item.label}</span><strong>{rows[item.id] ? `${rows[item.id].length}${hasMore[item.id] ? '+' : ''}` : '—'}</strong><small>View records →</small>
                </button>)}</div>
              <div className="info-panel"><h2>Offline by design</h2><p>Fleet has no standing connection to a strict-mode vessel. Signed receipt imports and verified product releases use an approved offline administrative process. This portal currently runs only in a synthetic local lab.</p></div>
            </>
          ) : (
            <>
              {section === 'releases' && <div className="info-panel"><h2>Import a signed release</h2><p>Use the local <code>services.fleet.release_import</code> command with a trusted public key. Fleet accepts only verified Core and Console product bundles. Lab approval is available after import; production approval remains a separate gate.</p></div>}
              {section === 'receipts' && <div className="info-panel"><h2>Signed offline receipts</h2><p>Enter the coded metadata and signature from an approved offline handoff. Fleet verifies the issuer key and signature before storing the receipt. Do not enter vessel documents, prompts or logs.</p></div>}
              <section className="table-panel" aria-label={`${current.label} records`}>
                <div className="panel-heading"><h2>{current.label} records</h2><span>{visible.length} shown{hasMore[section] ? ' · more available' : ''}</span></div>
                <div className="table-scroll"><table><thead><tr>{current.columns?.map((column) =>
                  <th key={column} scope="col">{column.replaceAll('_', ' ')}</th>)}
                  {nextStatuses[section] && <th scope="col">Next action</th>}</tr></thead><tbody>
                  {visible.map((row, index) => <tr key={String(row.code || row.seq || index)}>
                    {current.columns?.map((column) => <td key={column} title={String(row[column] ?? '')}>
                      {display(row[column], column)}</td>)}
                    {nextStatuses[section] && <td><div className="actions">
                      {(nextStatuses[section]?.[String(row.status)] || []).map((status) =>
                        <button type="button" key={status} disabled={loading} onClick={() =>
                          void changeStatus(String(row.code), status)}>{status.replaceAll('_', ' ')}</button>)}
                    </div></td>}
                  </tr>)}</tbody></table></div>
                {!visible.length && <p className="empty">No records in this section.</p>}
                {hasMore[section] && <div className="load-more"><button type="button" disabled={loading}
                  onClick={() => void loadMore()}>Load more records</button></div>}
              </section>
              {current.fields && <section className="form-panel"><h2>Add {current.label.toLowerCase()} record</h2>
                <p className="muted">Only structured company metadata is accepted. Enter codes and approved values.</p>
                <form onSubmit={(event) => void createRecord(event)} className="record-form">
                  {current.fields.map((field) => <label key={field.name}>{field.label}
                    {field.options ? <select value={form[field.name] || field.options[0]}
                      onChange={(event) => setForm({ ...form, [field.name]: event.target.value })}>
                      {field.options.map((option) => <option key={option} value={option}>{option.replaceAll('_', ' ')}</option>)}
                    </select> : <input type={field.type || 'text'} required value={form[field.name] || ''}
                      autoComplete="off" maxLength={40}
                      onChange={(event) => setForm({ ...form, [field.name]: event.target.value })} />}
                  </label>)}
                  <button type="submit" className="primary" disabled={loading}>Create record</button>
                </form>
              </section>}
              {section === 'receipts' && <section className="form-panel"><h2>Import signed receipt</h2>
                <p className="muted">The issuer must sign this exact metadata record offline. A modified field invalidates the signature.</p>
                <form onSubmit={(event) => void importReceipt(event)} className="record-form">
                  <label>Receipt code<input required autoComplete="off" maxLength={16}
                    value={receiptForm.code} onChange={(event) => setReceiptForm({ ...receiptForm, code: event.target.value })} /></label>
                  <label>Vessel code<input required autoComplete="off" maxLength={16}
                    value={receiptForm.vessel_code} onChange={(event) => setReceiptForm({ ...receiptForm, vessel_code: event.target.value })} /></label>
                  <label>Release code<input required autoComplete="off" maxLength={20}
                    value={receiptForm.release_code} onChange={(event) => setReceiptForm({ ...receiptForm, release_code: event.target.value })} /></label>
                  <label>Observed on<input required type="date" value={receiptForm.observed_on}
                    onChange={(event) => setReceiptForm({ ...receiptForm, observed_on: event.target.value })} /></label>
                  <label>Health<select value={receiptForm.health}
                    onChange={(event) => setReceiptForm({ ...receiptForm, health: event.target.value as ReceiptInput['health'] })}>
                    <option value="healthy">Healthy</option><option value="degraded">Degraded</option><option value="offline">Offline</option>
                  </select></label>
                  <label>Issuer key ID<input required autoComplete="off" minLength={64} maxLength={64} pattern="[0-9a-f]{64}"
                    value={receiptForm.key_id} onChange={(event) => setReceiptForm({ ...receiptForm, key_id: event.target.value })} /></label>
                  <label>Base64 signature<input required autoComplete="off" minLength={88} maxLength={88}
                    value={receiptForm.signature} onChange={(event) => setReceiptForm({ ...receiptForm, signature: event.target.value })} /></label>
                  <button type="submit" className="primary" disabled={loading}>Verify and import</button>
                </form>
              </section>}
            </>
          )}
        </div>
      </main>
    </div>
  )
}
