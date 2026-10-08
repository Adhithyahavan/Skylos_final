/**
 * AttackTimeline — Displays a visual timeline of incident events.
 */

interface TimelineEvent {
  id: number
  event_type: string
  message: string
  ip: string | null
  severity: string | null
  timestamp: string
}

interface AttackTimelineProps {
  events: TimelineEvent[]
}

export default function AttackTimeline({ events }: AttackTimelineProps) {
  if (!events.length) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
        No recent events
      </div>
    )
  }

  const formatTime = (ts: string) => {
    const d = new Date(ts)
    return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}:${d.getSeconds().toString().padStart(2, '0')}`
  }

  return (
    <div className="card" style={{ maxHeight: 400, overflowY: 'auto' }}>
      <h3 className="chart-title" style={{ marginBottom: '1.5rem' }}>Incident Timeline</h3>
      <div className="timeline">
        {events.map((event) => {
          let severityClass = ''
          if (event.event_type === 'alert') {
            if (event.severity === 'critical') severityClass = 'critical'
            else if (event.severity === 'high') severityClass = 'high'
            else severityClass = 'high'
          }

          return (
            <div key={event.id} className={`timeline-item ${severityClass}`} id={`timeline-event-${event.id}`}>
              <div className="tl-time">{formatTime(event.timestamp)}</div>
              <div className="tl-message">
                {event.event_type === 'alert' && <span className="badge badge-critical" style={{ marginRight: '0.5rem', fontSize: '0.6rem' }}>ALERT</span>}
                {event.message}
              </div>
              {event.ip && <div className="tl-ip">{event.ip}</div>}
            </div>
          )
        })}
      </div>
    </div>
  )
}
