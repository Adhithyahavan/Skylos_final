/**
 * Dashboard Page — Overview of system status, active alerts, and charts.
 */

import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar
} from 'recharts'

import { dashboardAPI, alertsAPI } from '../services/api'
import wsService, { WSMessage } from '../services/websocket'
import StatsCards from '../components/StatsCards'
import AttackTimeline from '../components/AttackTimeline'

export default function Dashboard() {
  const [stats, setStats] = useState<any>(null)
  const [timelineEvents, setTimelineEvents] = useState<any[]>([])
  const [loginData, setLoginData] = useState<any[]>([])
  const [alertData, setAlertData] = useState<any[]>([])
  const [topIPs, setTopIPs] = useState<any[]>([])
  const [recentAlerts, setRecentAlerts] = useState<any[]>([])
  const [toast, setToast] = useState<{ id: number; msg: string; type: string } | null>(null)

  const loadDashboardData = async () => {
    try {
      const [
        statsRes,
        timelineRes,
        loginRes,
        alertFreqRes,
        ipsRes,
        recentAlertsRes,
      ] = await Promise.all([
        dashboardAPI.stats(),
        dashboardAPI.timeline(),
        dashboardAPI.loginTimeline(),
        dashboardAPI.alertFrequency(),
        dashboardAPI.topSuspiciousIPs(),
        alertsAPI.getAll(0, 5, undefined),
      ])

      setStats(statsRes.data)
      setTimelineEvents(timelineRes.data)
      setLoginData(loginRes.data)
      setAlertData(alertFreqRes.data)
      setTopIPs(ipsRes.data)
      setRecentAlerts(recentAlertsRes.data)
    } catch (e) {
      console.error('Failed to load dashboard data', e)
    }
  }

  useEffect(() => {
    loadDashboardData()
    // Poll every 30s as a fallback
    const interval = setInterval(loadDashboardData, 30000)

    const unsub = wsService.onMessage((msg: WSMessage) => {
      if (msg.type === 'alert') {
        const al = msg.data
        // Show toast
        const toastId = Date.now()
        setToast({ id: toastId, msg: `[${al.severity.toUpperCase()}] ${al.message}`, type: al.severity })
        setTimeout(() => setToast(t => t?.id === toastId ? null : t), 5000)

        // Optimistically update lists
        setRecentAlerts(prev => [al, ...prev].slice(0, 5))
        setStats((prev: any) => prev ? { ...prev, active_alerts: prev.active_alerts + 1 } : prev)
        loadDashboardData() // Refresh charts
      } else if (msg.type === 'log') {
        setStats((prev: any) => prev ? { ...prev, total_logs: prev.total_logs + 1 } : prev)
      } else if (msg.type === 'network') {
        setStats((prev: any) => prev ? { ...prev, network_events: prev.network_events + 1 } : prev)
      }
    })

    return () => {
      clearInterval(interval)
      unsub()
    }
  }, [])

  return (
    <div className="dashboard-page fade-in">
      {/* Real-time Alert Toast */}
      {toast && (
        <div className="alert-toast-container">
          <div className="alert-toast">
            <span className="toast-icon">🚨</span>
            <div>
              <div className="toast-message">{toast.msg}</div>
              <div className="toast-time">Just now</div>
            </div>
          </div>
        </div>
      )}

      <div className="page-header">
        <h2>Security Overview</h2>
        <div className="header-actions">
          <span className="badge badge-normal" style={{ background: 'rgba(16, 185, 129, 0.1)', color: '#10b981', border: '1px solid currentColor' }}>
            <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: '#10b981', marginRight: 6 }}></span>
            System Operational
          </span>
        </div>
      </div>

      <StatsCards stats={stats} />

      <div className="charts-grid">
        {/* Logins Chart */}
        <div className="card">
          <h3 className="chart-title">Login Activity (24h)</h3>
          <div style={{ height: 260 }}>
            {loginData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={loginData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorLogins" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--accent-cyan)" stopOpacity={0.8}/>
                      <stop offset="95%" stopColor="var(--accent-cyan)" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                  <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={11} tickFormatter={(v) => v.split(' ')[1]} />
                  <YAxis stroke="var(--text-muted)" fontSize={11} />
                  <Tooltip 
                    contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '8px' }}
                    itemStyle={{ color: 'var(--text-primary)' }}
                  />
                  <Area type="monotone" dataKey="count" stroke="var(--accent-cyan)" fillOpacity={1} fill="url(#colorLogins)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="loading-spinner"><div className="spinner" /></div>
            )}
          </div>
        </div>

        {/* Alerts Chart */}
        <div className="card">
          <h3 className="chart-title">Threat Alerts Frequency</h3>
          <div style={{ height: 260 }}>
            {alertData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={alertData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                  <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={11} tickFormatter={(v) => v.split(' ')[1]} />
                  <YAxis stroke="var(--text-muted)" fontSize={11} />
                  <Tooltip 
                    contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '8px' }}
                    cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                  />
                  <Bar dataKey="count" fill="var(--accent-red)" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="loading-spinner"><div className="spinner" /></div>
            )}
          </div>
        </div>
      </div>

      <div className="charts-grid" style={{ gridTemplateColumns: 'minmax(400px, 2fr) minmax(300px, 1fr)' }}>
        {/* Timeline */}
        <AttackTimeline events={timelineEvents} />

        {/* Top Suspicious IPs */}
        <div className="card" style={{ maxHeight: 400, overflowY: 'auto' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
            <h3 className="chart-title" style={{ margin: 0 }}>Top Threat Sources</h3>
            <Link to="/network" className="btn btn-ghost" style={{ padding: '0.2rem 0.5rem', fontSize: '0.7rem' }}>View All</Link>
          </div>
          
          <table className="data-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Anomalies</th>
              </tr>
            </thead>
            <tbody>
              {topIPs.map((t) => (
                <tr key={t.ip}>
                  <td style={{ color: 'var(--accent-cyan)' }}>{t.ip}</td>
                  <td>
                    <span className="badge badge-anomaly" style={{ background: 'transparent' }}>
                      {t.count}
                    </span>
                  </td>
                </tr>
              ))}
              {topIPs.length === 0 && (
                <tr>
                  <td colSpan={2} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No threats detected</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
