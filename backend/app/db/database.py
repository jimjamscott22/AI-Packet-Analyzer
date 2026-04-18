import sqlite3

from app.core.config import get_settings


def get_connection() -> sqlite3.Connection:
    settings = get_settings()
    connection = sqlite3.connect(settings.db_path, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    connection = get_connection()
    cursor = connection.cursor()
    cursor.executescript(
        """
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            stored_path TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            error_message TEXT,
            progress REAL NOT NULL DEFAULT 0,
            packet_count INTEGER NOT NULL DEFAULT 0,
            flow_count INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS flows (
            id TEXT PRIMARY KEY,
            job_id TEXT NOT NULL,
            protocol TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            src_port INTEGER,
            dst_ip TEXT NOT NULL,
            dst_port INTEGER,
            first_seen TEXT,
            last_seen TEXT,
            packet_count INTEGER NOT NULL,
            byte_count INTEGER NOT NULL,
            duration_seconds REAL NOT NULL,
            score REAL NOT NULL,
            classification TEXT NOT NULL,
            directionality TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            llm_json TEXT,
            FOREIGN KEY(job_id) REFERENCES jobs(id)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            job_id TEXT NOT NULL,
            type TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            source TEXT NOT NULL,
            flow_ids_json TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            recommended_action TEXT,
            FOREIGN KEY(job_id) REFERENCES jobs(id)
        );

        CREATE INDEX IF NOT EXISTS idx_flows_job_protocol_score
        ON flows(job_id, protocol, score DESC);

        CREATE INDEX IF NOT EXISTS idx_findings_job_severity_confidence
        ON findings(job_id, severity, confidence DESC);
        """
    )
    connection.commit()
    connection.close()
