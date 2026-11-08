from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from app import models, schemas
from app.database import engine, get_db
from app.ai_agent import analyze_log

# Tworzenie tabel w bazie danych (jeśli nie istnieją)
def ensure_tables():
    try:
        models.Base.metadata.create_all(bind=engine)
    except Exception as e:
        print(f"⚠️ Uwaga: Oczekiwanie na bazę danych ({e})")

ensure_tables()

app = FastAPI(title="SOC AI Agent API", version="1.0")

@app.get("/")
def health_check(db: Session = Depends(get_db)):
    ensure_tables()
    # Szybki test czy potrafimy wejść w interakcję z bazą
    try:
        log_count = db.query(models.AnalyzedLog).count()
        db_status = "connected"
    except Exception:
        log_count = 0
        db_status = "unavailable"
    return {
        "status": "ok", 
        "database": db_status,
        "message": "Agent SOC nasłuchuje.",
        "logs_in_database": log_count
    }

@app.post("/logs/", response_model=schemas.SystemLogResponse)
def create_log(log: schemas.SystemLogCreate, db: Session = Depends(get_db)):
    ensure_tables()
    # Bezpośrednie zapisanie surowego logu do bazy z domyślnymi wartościami

    db_log = models.AnalyzedLog(
        source_ip=log.source_ip,
        event_type=log.event_type,
        description=log.description,
        is_malicious=False,
        threat_type="Unclassified",
        severity="low",
        reasoning="Zapis bezpośredni bez uprzedniej analizy AI"
    )
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log

@app.post("/analyze-test/")
def test_ai_analysis(log: schemas.SystemLogCreate):
    # Przekazujemy dane z żądania bezpośrednio do modelu AI
    analysis = analyze_log(log.source_ip, log.event_type, log.description)
    return analysis

@app.post("/analyze-and-save/", response_model=schemas.SystemLogResponse)
def analyze_and_save_log(log: schemas.SystemLogCreate, db: Session = Depends(get_db)):
    ensure_tables()
    # 1. Przekazanie logu do agenta AI
    ai_result = analyze_log(log.source_ip, log.event_type, log.description)
    
    # 2. Zapisanie surowych danych połączonych z analizą do bazy
    db_log = models.AnalyzedLog(
        source_ip=log.source_ip,
        event_type=log.event_type,
        description=log.description,
        is_malicious=ai_result.is_malicious,
        threat_type=ai_result.threat_type,
        severity=ai_result.severity,
        reasoning=ai_result.reasoning
    )
    
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    
    return db_log
