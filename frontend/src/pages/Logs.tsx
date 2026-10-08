/**
 * Logs Page — Raw system log viewer.
 */

import { useState, useEffect } from 'react'
import { logsAPI } from '../services/api'
import LogTable from '../components/LogTable'
import wsService, { WSMessage } from '../services/websocket'

export default function Logs() {
  const [logs, setLogs] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [anomalyOnly, setAnomalyOnly] = useState(false)

  const loadLogs = async () => {
    try {
      setLoading(true)
      const res = await logsAPI.getAll(0, 100, undefined, anomalyOnly)
      setLogs(res.data)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadLogs()

    const unsub = wsService.onMessage((msg: WSMessage) => {
      if (msg.type === 'log') {
        const newLog = msg.data
        if (anomalyOnly && !newLog.anomaly) return
        setLogs((prev) => [newLog, ...prev].slice(0, 100))
      }
    })

    return () => unsub()
  }, [anomalyOnly])

  return (
    <div className="logs-page fade-in">
      <div className="page-header">
        <h2>System Logs</h2>
        <div className="header-actions">
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.85rem' }}>
            <input 
              type="checkbox" 
              checked={anomalyOnly} 
              onChange={(e) => setAnomalyOnly(e.target.checked)}
              style={{ accentColor: 'var(--accent-red)' }}
            />
            Show Anomalies Only
          </label>
          <button className="btn btn-ghost" onClick={loadLogs}>
            🔄 Refresh
          </button>
        </div>
      </div>

      {loading ? (
        <div className="loading-spinner"><div className="spinner" /></div>
      ) : (
        <LogTable logs={logs} />
      )}
    </div>
  )
}
