/**
 * Login Page — Authenticates users and stores JWT tokens.
 */

import { useState } from 'react'
import { authAPI } from '../services/api'
import axios from 'axios'

interface LoginProps {
  onLogin: (token: string, username: string, role: string) => void
}

export default function Login({ onLogin }: LoginProps) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!username || !password) {
      setError('Please enter username and password')
      return
    }

    try {
      setLoading(true)
      setError('')
      const res = await authAPI.login(username, password)
      const { access_token, role, username: uName } = res.data
      onLogin(access_token, uName, role)
    } catch (err) {
      if (axios.isAxiosError(err) && err.response) {
        setError(err.response.data.detail || 'Login failed')
      } else {
        setError('Network error. Is backend running?')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-page fade-in">
      <div className="card login-card" style={{ maxWidth: 400 }}>
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div className="logo-icon" style={{ 
            width: 64, height: 64, margin: '0 auto 1.5rem', 
            background: 'var(--gradient-cyber)', borderRadius: 16,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: '2.5rem', boxShadow: '0 0 30px var(--glow-cyan)' 
          }}>
            🛡️
          </div>
          <h1>Skylos</h1>
          <div className="subtitle">Cybersecurity Monitoring Platform</div>
        </div>

        {error && <div className="form-error">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter username"
              autoComplete="username"
              required
            />
          </div>
          
          <div className="form-group" style={{ marginBottom: '2rem' }}>
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              autoComplete="current-password"
              required
            />
          </div>

          <button 
            type="submit" 
            className="btn btn-primary login-btn"
            style={{ width: '100%', justifyContent: 'center' }}
            disabled={loading}
          >
            {loading ? 'Authenticating...' : 'Secure Login →'}
          </button>
        </form>
        
        <div style={{ textAlign: 'center', marginTop: '1.5rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          First run? Create the administrator with <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>python manage.py create-admin</code>
        </div>
      </div>
    </div>
  )
}
