/**
 * Layout component — Sidebar navigation + main content area.
 */

import { NavLink, useLocation } from 'react-router-dom'
import { ReactNode } from 'react'

interface LayoutProps {
  children: ReactNode
  username: string
  role: string
  onLogout: () => void
}

export default function Layout({ children, username, role, onLogout }: LayoutProps) {
  const location = useLocation()

  const navItems = [
    { path: '/databases', label: 'Database Guardian', icon: 'DB' },
    { path: '/', label: 'Dashboard', icon: '📊' },
    { path: '/alerts', label: 'Threat Alerts', icon: '🚨' },
    { path: '/logs', label: 'System Logs', icon: '📋' },
    { path: '/network', label: 'Network Monitor', icon: '🌐' },
  ]

  return (
    <div className="app-layout">
      {/* Sidebar */}
      <nav className="sidebar" id="main-sidebar">
        <div className="sidebar-logo">
          <div className="logo-icon">🛡️</div>
          <div>
            <h1>AI-SIEM Guardian</h1>
            <span>Cyber Defense Platform</span>
          </div>
        </div>

        <div className="sidebar-nav">
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === '/'}
              className={({ isActive }) =>
                `nav-link${isActive ? ' active' : ''}`
              }
              id={`nav-${item.label.toLowerCase().replace(/\s+/g, '-')}`}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </div>

        {/* User info + logout */}
        <div style={{
          padding: '1rem 1.25rem',
          borderTop: '1px solid var(--border-color)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}>
          <div>
            <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>{username}</div>
            <div style={{
              fontSize: '0.7rem',
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
            }}>{role}</div>
          </div>
          <button
            onClick={onLogout}
            className="btn btn-ghost"
            style={{ padding: '0.4rem 0.75rem', fontSize: '0.75rem' }}
            id="logout-btn"
          >
            Logout
          </button>
        </div>
      </nav>

      {/* Main content */}
      <main className="main-content">
        {children}
      </main>
    </div>
  )
}
