/**
 * Alerts Page — Full threat alert management.
 */

import { useState, useEffect } from 'react'
import { alertsAPI, simulatorAPI } from '../services/api'
import AlertTable from '../components/AlertTable'
import wsService, { WSMessage } from '../services/websocket'

export default function Alerts() {
  const [alerts, setAlerts] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState<string>('all')
  const [simRunning, setSimRunning] = useState(false)

  const loadAlerts = async () => {
    try {
      setLoading(true)
      const severity = filter !== 'all' ? filter : undefined
      const res = await alertsAPI.getAll(0, 100, severity)
      setAlerts(res.data)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadAlerts()

    // Real-time updates
    const unsub = wsService.onMessage((msg: WSMessage) => {
      if (msg.type === 'alert') {
        setAlerts((prev) => [msg.data, ...prev])
      }
    })

    return () => unsub()
  }, [filter])

  const runSimulation = async () => {
    try {
      setSimRunning(true)
      await simulatorAPI.random()
      // Give backend a moment to process and return alerts via WS
      setTimeout(loadAlerts, 1000)
    } catch (e) {
      console.error(e)
    } finally {
      setSimRunning(false)
    }
  }

  return (
    <div className="alerts-page fade-in">
      <div className="page-header">
        <h2>Threat Alerts</h2>
        <div className="header-actions">
          <select 
            className="btn btn-ghost" 
            value={filter} 
            onChange={(e) => setFilter(e.target.value)}
            style={{ appearance: 'none', cursor: 'pointer', paddingRight: '2rem' }}
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical Only</option>
            <option value="high">High Only</option>
            <option value="medium">Medium</option>
          </select>

          <button 
            className="btn btn-danger" 
            onClick={runSimulation}
            disabled={simRunning}
            id="simulate-attack-btn"
          >
            {simRunning ? 'Simulating...' : '🔫 Simulate Attack'}
          </button>
        </div>
      </div>

      {loading ? (
        <div className="loading-spinner"><div className="spinner" /></div>
      ) : (
        <AlertTable alerts={alerts} onRefresh={loadAlerts} />
      )}
    </div>
  )
}
