/**
 * Network Monitor Page — Displays network traffic and IP activity.
 */

import { useState, useEffect } from 'react'
import { networkAPI } from '../services/api'

export default function NetworkMonitor() {
  const [activities, setActivities] = useState<any[]>([])
  const [topIPs, setTopIPs] = useState<any[]>([])
  const [stats, setStats] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [capturing, setCapturing] = useState(false)

  const loadNetworkData = async () => {
    try {
      setLoading(true)
      const [actRes, topRes, statRes] = await Promise.all([
        networkAPI.getActivity(0, 50, false),
        networkAPI.topIPs(),
        networkAPI.stats()
      ])
      setActivities(actRes.data)
      setTopIPs(topRes.data)
      setStats(statRes.data)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadNetworkData()
  }, [])

  const triggerCapture = async () => {
    try {
      setCapturing(true)
      await networkAPI.capture(100)
      await loadNetworkData()
    } catch (e) {
      console.error(e)
    } finally {
      setCapturing(false)
    }
  }

  const formatTime = (ts: string) => new Date(ts).toLocaleString()
  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  }

  return (
    <div className="network-page fade-in">
      <div className="page-header">
        <h2>Network Monitor</h2>
        <div className="header-actions">
          <button 
            className="btn btn-primary" 
            onClick={triggerCapture}
            disabled={capturing}
            id="capture-network-btn"
          >
            {capturing ? 'Capturing...' : '📡 Trigger Live Capture'}
          </button>
        </div>
      </div>

      {stats && (
        <div className="stats-grid" style={{ marginBottom: '1.5rem' }}>
          <div className="card stat-card">
            <div className="stat-label">Total Packets Evaluated</div>
            <div className="stat-value" style={{ color: 'var(--accent-blue)' }}>{stats.total_packets.toLocaleString()}</div>
          </div>
          <div className="card stat-card">
            <div className="stat-label">Data Monitored</div>
            <div className="stat-value" style={{ color: 'var(--accent-cyan)' }}>{formatBytes(stats.total_bytes)}</div>
          </div>
          <div className="card stat-card">
            <div className="stat-label">Unique Endpoints</div>
            <div className="stat-value" style={{ color: 'var(--accent-green)' }}>{stats.unique_ips}</div>
          </div>
          <div className="card stat-card">
            <div className="stat-label">Suspicious IPs Flagged</div>
            <div className="stat-value" style={{ color: 'var(--accent-red)' }}>{stats.suspicious_count}</div>
          </div>
        </div>
      )}

      <div className="charts-grid" style={{ gridTemplateColumns: '1fr 2fr' }}>
        {/* Top IPs */}
        <div className="card" style={{ maxHeight: 500, overflowY: 'auto' }}>
          <h3 className="chart-title">Traffic by Origin IP</h3>
          <table className="data-table">
            <thead>
              <tr>
                <th>IP</th>
                <th>Packets</th>
              </tr>
            </thead>
            <tbody>
              {topIPs.map(ip => (
                <tr key={ip.ip}>
                  <td style={{ color: ip.suspicious ? 'var(--accent-red)' : 'var(--accent-cyan)' }}>
                    {ip.ip}
                    {ip.suspicious && <span style={{ marginLeft: 6, fontSize: '0.8em' }}>⚠</span>}
                  </td>
                  <td>{ip.packets.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Live Event Stream */}
        <div className="card" style={{ maxHeight: 500, overflowY: 'auto' }}>
          <h3 className="chart-title">Recent Packet Captures</h3>
          {loading ? (
             <div className="loading-spinner"><div className="spinner" /></div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Origin IP</th>
                  <th>Protocol</th>
                  <th>Packets Block</th>
                  <th>Size</th>
                  <th>Eval Status</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {activities.map(act => (
                  <tr key={act.id}>
                    <td style={{ color: 'var(--accent-cyan)' }}>{act.ip}</td>
                    <td><span className="badge badge-normal">{act.protocol}</span></td>
                    <td>{act.packets} pkts</td>
                    <td>{formatBytes(act.bytes_transferred)}</td>
                    <td>
                      {act.suspicious 
                        ? <span className="badge badge-critical">Suspicious</span>
                        : <span className="badge badge-normal" style={{ background: 'rgba(16, 185, 129, 0.1)', color: '#10b981', border: 'none' }}>Clean</span>
                      }
                    </td>
                    <td style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{formatTime(act.timestamp)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}
