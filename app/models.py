from sqlalchemy import Column, Integer, String, DateTime, Boolean
from datetime import datetime
from app.database import Base

class AnalyzedLog(Base):
    __tablename__ = "analyzed_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    source_ip = Column(String, index=True)
    event_type = Column(String, index=True)
    description = Column(String)
    
    # Wnioski od AI
    is_malicious = Column(Boolean, default=False)
    threat_type = Column(String, default="None")
    severity = Column(String, default="info")
    reasoning = Column(String, default="")

# Alias zapewniający kompatybilność wsteczną
SystemLog = AnalyzedLog
