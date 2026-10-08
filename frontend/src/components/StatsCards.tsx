/**
 * StatsCards — Overview statistic cards for the dashboard.
 */

interface StatsCardsProps {
  stats: {
    total_logs: number
    active_alerts: number
    network_events: number
    anomalies_detected: number
    system_status: string
  } | null
}

export default function StatsCards({ stats }: StatsCardsProps) {
  if (!stats) {
    return (
      <div className="stats-grid">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="card stat-card" style={{ minHeight: 100 }}>
            <div className="loading-spinner"><div className="spinner" /></div>
          </div>
        ))}
      </div>
    )
  }

  const cards = [
    {
      icon: '📋',
      label: 'Total Logs',
      value: stats.total_logs.toLocaleString(),
      color: 'var(--accent-cyan)',
    },
    {
      icon: '🚨',
      label: 'Active Alerts',
      value: stats.active_alerts.toLocaleString(),
      color: 'var(--accent-red)',
    },
    {
      icon: '🌐',
      label: 'Network Events',
      value: stats.network_events.toLocaleString(),
      color: 'var(--accent-blue)',
    },
    {
      icon: '🤖',
      label: 'Anomalies',
      value: stats.anomalies_detected.toLocaleString(),
      color: 'var(--accent-purple)',
    },
  ]

  return (
    <div className="stats-grid">
      {cards.map((card, i) => (
        <div key={i} className="card stat-card" id={`stat-${card.label.toLowerCase().replace(/\s+/g, '-')}`}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="stat-label">{card.label}</span>
            <span className="stat-icon">{card.icon}</span>
          </div>
          <div className="stat-value" style={{ color: card.color }}>
            {card.value}
          </div>
          <div style={{
            fontSize: '0.7rem',
            color: 'var(--text-muted)',
            marginTop: '0.25rem',
          }}>
            System: {stats.system_status}
          </div>
        </div>
      ))}
    </div>
  )
}
