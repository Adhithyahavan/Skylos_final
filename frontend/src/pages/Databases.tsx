import { FormEvent, useEffect, useState } from 'react'
import axios from 'axios'
import { databasesAPI } from '../services/api'

type DatabaseAsset = {
  id: number
  name: string
  db_type: 'sqlite' | 'postgresql'
  host?: string | null
  port?: number | null
  database_name: string
  is_active: boolean
  status: string
  risk_score: number
}

export default function Databases() {
  const role = localStorage.getItem('role') || 'viewer'
  const isAdmin = role === 'admin'
  const canTestConnections = isAdmin || role === 'analyst'
  const [databases, setDatabases] = useState<DatabaseAsset[]>([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [details, setDetails] = useState<{ id: number; risk: any; alerts: any[] } | null>(null)
  const [form, setForm] = useState({
    name: '', db_type: 'postgresql' as 'sqlite' | 'postgresql', host: '', port: '5432',
    database_name: '', username: '', password: '',
  })

  const loadDatabases = async () => {
    try {
      setError('')
      const response = await databasesAPI.getAll()
      setDatabases(response.data)
    } catch (err) {
      setError(axios.isAxiosError(err) ? err.response?.data?.detail || 'Could not load databases.' : 'Could not load databases.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { void loadDatabases() }, [])

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setSaving(true)
    setError('')
    setNotice('')
    try {
      await databasesAPI.register({
        name: form.name.trim(),
        db_type: form.db_type,
        ...(form.db_type === 'postgresql' ? { host: form.host.trim(), port: Number(form.port) } : {}),
        database_name: form.database_name.trim(),
        username: form.username.trim(),
        password: form.password,
      })
      setForm({ name: '', db_type: 'postgresql', host: '', port: '5432', database_name: '', username: '', password: '' })
      setNotice('Database registered. Use Test connection to check its credentials.')
      await loadDatabases()
    } catch (err) {
      setError(axios.isAxiosError(err) ? err.response?.data?.detail || 'Could not register database.' : 'Could not register database.')
    } finally {
      setSaving(false)
    }
  }

  const testConnection = async (asset: DatabaseAsset) => {
    setNotice('')
    setError('')
    try {
      const response = await databasesAPI.testConnection(asset.id)
      setNotice(`Connection succeeded for ${asset.name}. ${response.data.version || ''}`)
      await loadDatabases()
    } catch (err) {
      setError(axios.isAxiosError(err) ? err.response?.data?.detail || `Could not connect to ${asset.name}.` : `Could not connect to ${asset.name}.`)
    }
  }

  const toggleMonitoring = async (asset: DatabaseAsset) => {
    try {
      await databasesAPI.update(asset.id, { is_active: !asset.is_active })
      await loadDatabases()
    } catch (err) {
      setError(axios.isAxiosError(err) ? err.response?.data?.detail || 'Could not update monitoring.' : 'Could not update monitoring.')
    }
  }

  const showDetails = async (asset: DatabaseAsset) => {
    setError('')
    try {
      const [risk, alerts] = await Promise.all([
        databasesAPI.riskScore(asset.id),
        databasesAPI.alerts(asset.id, { limit: 10 }),
      ])
      setDetails({ id: asset.id, risk: risk.data, alerts: alerts.data })
    } catch (err) {
      setError(axios.isAxiosError(err) ? err.response?.data?.detail || 'Could not load database details.' : 'Could not load database details.')
    }
  }

  return (
    <div className="fade-in">
      <div className="page-header"><h2>Database Guardian</h2></div>
      {error && <div className="form-error" role="alert">{error}</div>}
      {notice && <div className="card" role="status" style={{ marginBottom: '1rem' }}>{notice}</div>}

      {isAdmin && <section className="card" style={{ marginBottom: '1.5rem' }}>
        <h3>Register a database</h3>
        <form onSubmit={submit} className="database-form">
          <div className="form-group"><label htmlFor="db-name">Display name</label>
            <input id="db-name" required maxLength={100} value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
          </div>
          <div className="form-group"><label htmlFor="db-type">Database type</label>
            <select id="db-type" value={form.db_type} onChange={e => setForm({ ...form, db_type: e.target.value as 'sqlite' | 'postgresql' })}>
              <option value="postgresql">PostgreSQL</option><option value="sqlite">SQLite</option>
            </select>
          </div>
          {form.db_type === 'postgresql' && <>
            <div className="form-group"><label htmlFor="db-host">Host</label>
              <input id="db-host" required maxLength={255} value={form.host} onChange={e => setForm({ ...form, host: e.target.value })} />
            </div>
            <div className="form-group"><label htmlFor="db-port">Port</label>
              <input id="db-port" type="number" required min={1} max={65535} value={form.port} onChange={e => setForm({ ...form, port: e.target.value })} />
            </div>
          </>}
          <div className="form-group"><label htmlFor="db-name-or-path">Database name or SQLite path</label>
            <input id="db-name-or-path" required maxLength={100} value={form.database_name} onChange={e => setForm({ ...form, database_name: e.target.value })} />
          </div>
          <div className="form-group"><label htmlFor="db-user">Username</label>
            <input id="db-user" required maxLength={100} autoComplete="off" value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} />
          </div>
          <div className="form-group"><label htmlFor="db-password">Password</label>
            <input id="db-password" type="password" required maxLength={255} autoComplete="new-password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} />
          </div>
          <button className="btn btn-primary" type="submit" disabled={saving}>{saving ? 'Saving…' : 'Register database'}</button>
        </form>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>Credentials are encrypted before they are stored. Only SQLite and PostgreSQL are supported.</p>
      </section>}

      <section className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3>Registered databases</h3><button className="btn btn-ghost" onClick={() => void loadDatabases()}>Refresh</button>
        </div>
        {loading ? <p>Loading databases…</p> : databases.length === 0 ? <p>No databases registered yet.</p> : (
          <div>
            {databases.map(asset => <article key={asset.id} className="card" style={{ marginTop: '1rem' }}>
              <strong>{asset.name}</strong>
              <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>{asset.db_type} · {asset.host ? `${asset.host}:${asset.port}/` : ''}{asset.database_name}</div>
              <p>Status: {asset.status} · Risk: {asset.risk_score} · Monitoring: {asset.is_active ? 'On' : 'Off'}</p>
              <div className="header-actions">
                {canTestConnections && <button className="btn btn-ghost" onClick={() => void testConnection(asset)}>Test connection</button>}
                {isAdmin && <button className="btn btn-ghost" onClick={() => void toggleMonitoring(asset)}>{asset.is_active ? 'Pause' : 'Resume'}</button>}
                <button className="btn btn-ghost" onClick={() => void showDetails(asset)}>Risk and alerts</button>
              </div>
            </article>)}
          </div>
        )}
      </section>

      {details && <section className="card" style={{ marginTop: '1.5rem' }}>
        <h3>Database risk and recent alerts</h3><p>Risk score: {details.risk.total_risk_score}</p>
        {details.alerts.length === 0 ? <p>No alerts for this database.</p> : <ul>
          {details.alerts.map((alert: any) => <li key={alert.id}>{alert.severity.toUpperCase()} · {alert.title} · {new Date(alert.timestamp).toLocaleString()}</li>)}
        </ul>}
      </section>}
    </div>
  )
}
