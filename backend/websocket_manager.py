"""
AI-SIEM Guardian — WebSocket Manager
Manages WebSocket connections and broadcasts real-time alerts to all clients.
"""

from typing import List
from fastapi import WebSocket
import json
import logging

logger = logging.getLogger(__name__)


class WebSocketManager:
    """
    Keeps track of active WebSocket connections and provides broadcast
    functionality for pushing real-time alerts to the dashboard.
    """

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Accept a new WebSocket connection and add it to the pool."""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection from the pool."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def send_personal(self, message: dict, websocket: WebSocket):
        """Send a JSON message to a single client."""
        await websocket.send_json(message)

    async def broadcast(self, message: dict):
        """
        Broadcast a JSON message to ALL connected clients.
        Automatically removes dead connections.
        """
        dead = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead.append(connection)
        # Clean up broken connections
        for conn in dead:
            self.disconnect(conn)

    async def broadcast_alert(self, alert_data: dict):
        """Convenience wrapper — broadcasts an alert-type event."""
        message = {
            "type": "alert",
            "data": alert_data,
        }
        await self.broadcast(message)

    async def broadcast_log(self, log_data: dict):
        """Broadcast a new log event to all listeners."""
        message = {
            "type": "log",
            "data": log_data,
        }
        await self.broadcast(message)

    async def broadcast_network(self, network_data: dict):
        """Broadcast network activity data."""
        message = {
            "type": "network",
            "data": network_data,
        }
        await self.broadcast(message)


# Global singleton instance used across the application
ws_manager = WebSocketManager()
