import { Routes, Route, Navigate } from 'react-router-dom'
import { lazy, Suspense, useState, useEffect } from 'react'
import Layout from './components/Layout'
import Login from './pages/Login'
import wsService from './services/websocket'

const Dashboard = lazy(() => import('./pages/Dashboard'))
const Alerts = lazy(() => import('./pages/Alerts'))
const Logs = lazy(() => import('./pages/Logs'))
const NetworkMonitor = lazy(() => import('./pages/NetworkMonitor'))
const Databases = lazy(() => import('./pages/Databases'))

function App() {
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'))
  const [username, setUsername] = useState<string>(localStorage.getItem('username') || '')
  const [role, setRole] = useState<string>(localStorage.getItem('role') || '')

  const handleLogin = (t: string, u: string, r: string) => {
    setToken(t)
    setUsername(u)
    setRole(r)
    localStorage.setItem('token', t)
    localStorage.setItem('username', u)
    localStorage.setItem('role', r)
  }

  const handleLogout = () => {
    wsService.disconnect()
    setToken(null)
    setUsername('')
    setRole('')
    localStorage.removeItem('token')
    localStorage.removeItem('username')
    localStorage.removeItem('role')
  }

  useEffect(() => {
    if (!token) return
    wsService.connect()
    return () => wsService.disconnect()
  }, [token])

  if (!token) {
    return <Login onLogin={handleLogin} />
  }

  return (
    <Layout username={username} role={role} onLogout={handleLogout}>
      <Suspense fallback={<div className="loading-spinner"><div className="spinner" /></div>}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/logs" element={<Logs />} />
          <Route path="/network" element={<NetworkMonitor />} />
          <Route path="/databases" element={<Databases />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Suspense>
    </Layout>
  )
}

export default App
