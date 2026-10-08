/**
 * AI-SIEM Guardian — API Service
 * Axios client with JWT interceptor and typed methods for all endpoints.
 */

import axios from 'axios'

const API_BASE = '/api'

const api = axios.create({
  baseURL: API_BASE,
  headers: { 'Content-Type': 'application/json' },
})

// ── JWT Interceptor ─────────────────────────────────────────────
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (res) => res,
  (err) => {
    const isLoginRequest = err.config?.url?.includes('/auth/login')
    if (err.response?.status === 401 && !isLoginRequest) {
      localStorage.removeItem('token')
      window.location.href = '/'
    }
    return Promise.reject(err)
  }
)

// ── Auth ────────────────────────────────────────────────────────
export const authAPI = {
  login: (username: string, password: string) =>
    api.post('/auth/login', { username, password }),
  register: (username: string, email: string, password: string, role = 'viewer') =>
    api.post('/auth/register', { username, email, password, role }),
  me: () => api.get('/auth/me'),
}

// ── Logs ────────────────────────────────────────────────────────
export const logsAPI = {
  getAll: (skip = 0, limit = 50, eventType?: string, anomalyOnly = false) =>
    api.get('/logs/', { params: { skip, limit, event_type: eventType, anomaly_only: anomalyOnly } }),
  ingest: (log: any) => api.post('/logs/ingest', log),
  count: () => api.get('/logs/count'),
}

// ── Normalized security events ──────────────────────────────────────────────
export const eventsAPI = {
  getAll: (params: {
    skip?: number
    limit?: number
    event_type?: string
    source_type?: string
    since?: string
    until?: string
  } = {}) => api.get('/events/', { params }),
}

// ── Alerts ──────────────────────────────────────────────────────
export const alertsAPI = {
  getAll: (skip = 0, limit = 50, severity?: string) =>
    api.get('/alerts/', { params: { skip, limit, severity } }),
  count: () => api.get('/alerts/count'),
  acknowledge: (id: number) =>
    api.patch(`/alerts/${id}/acknowledge`, { acknowledged: true }),
}

// ── Network ─────────────────────────────────────────────────────
export const networkAPI = {
  capture: (count = 50) => api.post('/network/capture', null, { params: { count } }),
  getActivity: (skip = 0, limit = 50, suspiciousOnly = false) =>
    api.get('/network/activity', { params: { skip, limit, suspicious_only: suspiciousOnly } }),
  topIPs: () => api.get('/network/top-ips'),
  stats: () => api.get('/network/stats'),
}

// ── Dashboard ───────────────────────────────────────────────────
export const dashboardAPI = {
  stats: () => api.get('/dashboard/stats'),
  timeline: (limit = 20) => api.get('/dashboard/timeline', { params: { limit } }),
  loginTimeline: () => api.get('/dashboard/login-timeline'),
  alertFrequency: () => api.get('/dashboard/alert-frequency'),
  topSuspiciousIPs: () => api.get('/dashboard/top-suspicious-ips'),
}

// ── Attack Simulator ────────────────────────────────────────────
export const simulatorAPI = {
  random: () => api.post('/simulator/random'),
  all: () => api.post('/simulator/all'),
}

// ── Database Guardian ──────────────────────────────────────────────────────
export const databasesAPI = {
  getAll: () => api.get('/databases/'),
  get: (id: number) => api.get(`/databases/${id}`),
  register: (database: {
    name: string
    db_type: 'sqlite' | 'postgresql'
    host?: string
    port?: number
    database_name: string
    username: string
    password: string
  }) => api.post('/databases/', database),
  update: (id: number, changes: { name?: string; is_active?: boolean }) =>
    api.patch(`/databases/${id}`, changes),
  testConnection: (id: number) => api.post(`/databases/${id}/test-connection`),
  alerts: (id: number, params: { skip?: number; limit?: number; acknowledged?: boolean } = {}) =>
    api.get(`/databases/${id}/alerts`, { params }),
  riskScore: (id: number) => api.get(`/databases/${id}/risk-score`),
}

export default api
