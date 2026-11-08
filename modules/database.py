import os
from dotenv import load_dotenv
import pandas as pd
from sqlalchemy import create_engine, text

load_dotenv()

def fix_postgres_url(url: str) -> str:
    """Zapewnia kompatybilność ze sterownikiem psycopg2 gdy brak psycopg 3."""
    if url.startswith("postgresql://"):
        try:
            import psycopg  # noqa: F401
        except ImportError:
            url = url.replace("postgresql://", "postgresql+psycopg2://", 1)
    return url

def get_database_url() -> str:
    """Zwraca URL bazy danych uwzględniając środowisko Docker vs lokalne."""
    env_url = os.getenv("DATABASE_URL")
    if env_url:
        return fix_postgres_url(env_url)
    if os.path.exists("/.dockerenv"):
        return fix_postgres_url("postgresql://postgres:admin_password@db:5432/soc_db")
    return fix_postgres_url("postgresql://postgres:admin_password@localhost:5433/soc_db")

DB_URL = get_database_url()
engine = create_engine(DB_URL)


def init_db():
    """Tworzy tabelę analyzed_logs jeśli jeszcze nie istnieje."""
    create_table_query = """
    CREATE TABLE IF NOT EXISTS analyzed_logs (
        id SERIAL PRIMARY KEY,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        source_ip VARCHAR(64),
        event_type VARCHAR(64),
        description TEXT,
        is_malicious BOOLEAN DEFAULT FALSE,
        threat_type VARCHAR(64),
        severity VARCHAR(32),
        reasoning TEXT
    );
    """
    try:
        with engine.connect() as conn:
            conn.execute(text(create_table_query))
            conn.commit()
    except Exception:
        pass

def load_data() -> pd.DataFrame:
    """
    Ładuje przeanalizowane logi z bazy danych.
    W przypadku braku połączenia lub braku tabeli zwraca pusty DataFrame z poprawnym schematem.
    """
    query = "SELECT * FROM analyzed_logs ORDER BY timestamp DESC"
    try:
        init_db()
        return pd.read_sql(query, engine)
    except Exception:
        return pd.DataFrame(columns=[
            "id", "timestamp", "source_ip", "event_type", 
            "description", "is_malicious", "threat_type", "severity", "reasoning"
        ])

def clear_logs() -> int:
    """
    Usuwa wszystkie rekordy z tabeli analyzed_logs.
    Zwraca liczbę usuniętych wierszy.
    """
    with engine.connect() as conn:
        result = conn.execute(text("DELETE FROM analyzed_logs"))
        conn.commit()
        return result.rowcount

