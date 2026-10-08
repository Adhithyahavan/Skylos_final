/**
 * AI-SIEM Guardian — WebSocket Service
 * Connects to backend WebSocket for real-time alerts, logs, and network events.
 */

export type WSEventType = 'alert' | 'log' | 'network' | 'pong'

export interface WSMessage {
  type: WSEventType
  data: any
}

type Listener = (message: WSMessage) => void

class WebSocketService {
  private ws: WebSocket | null = null
  private listeners: Listener[] = []
  private reconnectAttempts = 0
  private maxReconnectAttempts = 10
  private reconnectDelay = 2000
  private shouldReconnect = false
  private baseUrl: string

  constructor() {
    // Use relative WebSocket URL — Vite proxy handles it in dev
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    this.baseUrl = `${protocol}//${window.location.host}/ws`
  }

  /** Connect to the WebSocket server */
  connect(): void {
    if (this.ws?.readyState === WebSocket.OPEN || this.ws?.readyState === WebSocket.CONNECTING) return
    if (!this.shouldReconnect) this.reconnectAttempts = 0
    this.shouldReconnect = true

    const token = localStorage.getItem('token')
    if (!token) return

    try {
      const socket = new WebSocket(`${this.baseUrl}?token=${encodeURIComponent(token)}`)
      this.ws = socket

      socket.onopen = () => {
        if (this.ws !== socket) return
        console.log('[WS] Connected')
        this.reconnectAttempts = 0
      }

      socket.onmessage = (event) => {
        if (this.ws !== socket) return
        try {
          const message: WSMessage = JSON.parse(event.data)
          this.listeners.forEach((fn) => fn(message))
        } catch (e) {
          console.warn('[WS] Failed to parse message', e)
        }
      }

      socket.onclose = () => {
        if (this.ws !== socket) return
        console.log('[WS] Disconnected')
        this.ws = null
        if (this.shouldReconnect) this.tryReconnect()
      }

      socket.onerror = (err) => {
        console.error('[WS] Error', err)
      }
    } catch (e) {
      console.error('[WS] Connection failed', e)
      this.tryReconnect()
    }
  }

  /** Disconnect from the server */
  disconnect(): void {
    this.shouldReconnect = false
    this.reconnectAttempts = 0
    const socket = this.ws
    this.ws = null
    socket?.close()
  }

  /** Subscribe to incoming messages */
  onMessage(fn: Listener): () => void {
    this.listeners.push(fn)
    // Return unsubscribe function
    return () => {
      this.listeners = this.listeners.filter((l) => l !== fn)
    }
  }

  /** Send a message to the server */
  send(data: string): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(data)
    }
  }

  private tryReconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.warn('[WS] Max reconnect attempts reached')
      return
    }
    this.reconnectAttempts++
    const delay = this.reconnectDelay * this.reconnectAttempts
    console.log(`[WS] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`)
    setTimeout(() => {
      if (this.shouldReconnect) this.connect()
    }, delay)
  }
}

// Global singleton
const wsService = new WebSocketService()
export default wsService
