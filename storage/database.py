import sqlite3
import json
from pathlib import Path


# Database file location
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "securehost.db"

# SQL schema location
SCHEMA_PATH = BASE_DIR / "schema.sql"


def get_connection():
    """Create a connection to the SQLite database."""

    connection = sqlite3.connect(DB_PATH)

    # Enable foreign key support
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def initialize_database():
    """Create database tables using schema.sql."""

    connection = get_connection()

    with open(SCHEMA_PATH, "r") as schema_file:
        schema = schema_file.read()

    connection.executescript(schema)
    connection.commit()
    connection.close()


def save_event(event):
    """Save a SecurityEvent and return its database ID."""

    connection = get_connection()

    cursor = connection.execute(
        """
        INSERT INTO events (
            timestamp_utc,
            category,
            source,
            subject,
            action,
            details_json
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            event.timestamp_utc,
            event.category,
            event.source,
            event.subject,
            event.action,
            json.dumps(event.details),
        ),
    )

    event_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return event_id


def save_alert(event_id, alert):
    """Save a SecurityAlert linked to its original event."""

    connection = get_connection()

    connection.execute(
        """
        INSERT INTO alerts (
            event_id,
            rule_id,
            severity,
            reason,
            dedup_key
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            event_id,
            alert.rule_id,
            alert.severity,
            alert.reason,
            alert.dedup_key,
        ),
    )

    connection.commit()
    connection.close()
