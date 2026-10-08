"""
Database Connector - Multi-database connection management.
Supports SQLite and PostgreSQL with extensible architecture.
"""
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod
import sqlite3
import psycopg2
import os
from secret_provider import get_secret_provider

class DatabaseConnector(ABC):
    """Abstract base class for database connections."""

    @abstractmethod
    def connect(self) -> Any:
        """Establish connection to database."""
        pass

    @abstractmethod
    def execute_query(self, query: str) -> list:
        """Execute a query and return results."""
        pass

    @abstractmethod
    def get_database_version(self) -> str:
        """Get database version."""
        pass

    @abstractmethod
    def get_database_size_mb(self) -> int:
        """Get database size in MB."""
        pass

    @abstractmethod
    def close(self):
        """Close connection."""
        pass

class SQLiteConnector(DatabaseConnector):
    """SQLite database connector."""

    def __init__(self, database_path: str):
        self.database_path = database_path
        self.conn = None

    def connect(self):
        self.conn = sqlite3.connect(self.database_path)
        return self.conn

    def execute_query(self, query: str) -> list:
        cursor = self.conn.cursor()
        cursor.execute(query)
        return cursor.fetchall()

    def get_database_version(self) -> str:
        result = self.execute_query("SELECT sqlite_version()")
        return result[0][0] if result else "unknown"

    def get_database_size_mb(self) -> int:
        if os.path.exists(self.database_path):
            return os.path.getsize(self.database_path) // (1024 * 1024)
        return 0

    def close(self):
        if self.conn:
            self.conn.close()

class PostgreSQLConnector(DatabaseConnector):
    """PostgreSQL database connector."""

    def __init__(self, host: str, port: int, database: str, username: str, encrypted_password: str):
        self.host = host
        self.port = port
        self.database = database
        self.username = username
        # Decrypted only inside the backend, at connection time (SecretProvider)
        self.password = get_secret_provider().decrypt(encrypted_password)
        self.conn = None

    def connect(self):
        self.conn = psycopg2.connect(
            host=self.host,
            port=self.port,
            database=self.database,
            user=self.username,
            password=self.password,
            connect_timeout=5,
        )
        return self.conn

    def execute_query(self, query: str) -> list:
        cursor = self.conn.cursor()
        cursor.execute(query)
        return cursor.fetchall()

    def get_database_version(self) -> str:
        result = self.execute_query("SELECT version()")
        return result[0][0] if result else "unknown"

    def get_database_size_mb(self) -> int:
        cursor = self.conn.cursor()
        cursor.execute("SELECT pg_database_size(%s) / (1024 * 1024)", (self.database,))
        result = cursor.fetchall()
        return int(result[0][0]) if result else 0

    def close(self):
        if self.conn:
            self.conn.close()

def create_connector(db_asset) -> DatabaseConnector:
    """Factory function to create appropriate connector."""
    if db_asset.db_type == "sqlite":
        return SQLiteConnector(db_asset.database_name)
    elif db_asset.db_type == "postgresql":
        return PostgreSQLConnector(
            db_asset.host,
            db_asset.port,
            db_asset.database_name,
            db_asset.username,
            db_asset.encrypted_password
        )
    else:
        raise ValueError(f"Unsupported database type: {db_asset.db_type}")
