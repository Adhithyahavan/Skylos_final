/**
 * AlertTable — Displays alerts with severity badges, filtering, and acknowledge action.
 */

import { alertsAPI } from '../services/api'

interface Alert {
  id: number
  log_id: number | null
  severity: string
  message: string
  ip: string | null
  alert_type: string | null
  acknowledged: boolean
  timestamp: string
}

interface AlertTableProps {
  alerts: Alert[]
  onRefresh?: () => void
}

export default function AlertTable({ alerts, onRefresh }: AlertTableProps) {
  const handleAcknowledge = async (id: number) => {
    try {
      await alertsAPI.acknowledge(id)
      onRefresh?.()
    } catch (e) {
      console.error('Failed to acknowledge alert', e)
    }
  }

  const getSeverityBadge = (severity: string) => {
    const cls = `badge badge-${severity}`
    return <span className={cls}>{severity}</span>
  }

  const formatTime = (ts: string) => {
    const d = new Date(ts)
    return d.toLocaleString()
  }

  if (!alerts.length) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
        No alerts found
      </div>
    )
  }

  return (
    <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
      <table className="data-table" id="alert-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Message</th>
            <th>IP Address</th>
            <th>Type</th>
            <th>Time</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id} style={{
              opacity: alert.acknowledged ? 0.5 : 1,
            }}>
              <td>{getSeverityBadge(alert.severity)}</td>
              <td style={{ fontFamily: 'var(--font-sans)', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {alert.message}
              </td>
              <td style={{ color: 'var(--accent-cyan)' }}>{alert.ip || '—'}</td>
              <td>
                <span className="badge badge-normal">{alert.alert_type || 'unknown'}</span>
              </td>
              <td style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                {formatTime(alert.timestamp)}
              </td>
              <td>
                {!alert.acknowledged && (
                  <button
                    className="btn btn-ghost"
                    style={{ padding: '0.3rem 0.6rem', fontSize: '0.7rem' }}
                    onClick={() => handleAcknowledge(alert.id)}
                  >
                    Acknowledge
                  </button>
                )}
                {alert.acknowledged && (
                  <span style={{ fontSize: '0.75rem', color: 'var(--accent-green)' }}>✓ Ack</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
