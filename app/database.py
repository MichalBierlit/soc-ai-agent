import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

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


SQLALCHEMY_DATABASE_URL = get_database_url()

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Funkcja pomocnicza do pobierania sesji bazy danych
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
