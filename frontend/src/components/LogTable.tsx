/**
 * LogTable — Displays system logs with anomaly highlighting and filtering.
 */

interface LogEntry {
  id: number
  user: string | null
  ip: string
  event_type: string
  failed_attempts: number
  login_frequency: number
  ip_activity_rate: number
  anomaly: boolean
  timestamp: string
}

interface LogTableProps {
  logs: LogEntry[]
}

export default function LogTable({ logs }: LogTableProps) {
  const formatTime = (ts: string) => new Date(ts).toLocaleString()

  if (!logs.length) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
        No logs found
      </div>
    )
  }

  return (
    <div className="card" style={{ padding: 0, overflow: 'auto' }}>
      <table className="data-table" id="log-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>User</th>
            <th>IP Address</th>
            <th>Event</th>
            <th>Failed</th>
            <th>Freq</th>
            <th>IP Rate</th>
            <th>Status</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log) => (
            <tr
              key={log.id}
              style={{
                background: log.anomaly ? 'rgba(239, 68, 68, 0.05)' : undefined,
                borderLeft: log.anomaly ? '3px solid var(--accent-red)' : undefined,
              }}
            >
              <td style={{ color: 'var(--text-muted)' }}>#{log.id}</td>
              <td>{log.user || '—'}</td>
              <td style={{ color: 'var(--accent-cyan)' }}>{log.ip}</td>
              <td>
                <span className={`badge ${log.event_type === 'login' ? 'badge-medium' : log.event_type === 'security' ? 'badge-high' : 'badge-normal'}`}>
                  {log.event_type}
                </span>
              </td>
              <td style={{ color: log.failed_attempts > 3 ? 'var(--accent-red)' : 'var(--text-secondary)' }}>
                {log.failed_attempts}
              </td>
              <td>{log.login_frequency.toFixed(1)}</td>
              <td>{log.ip_activity_rate.toFixed(1)}</td>
              <td>
                {log.anomaly ? (
                  <span className="badge badge-anomaly">⚠ Anomaly</span>
                ) : (
                  <span className="badge badge-normal">Normal</span>
                )}
              </td>
              <td style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                {formatTime(log.timestamp)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
