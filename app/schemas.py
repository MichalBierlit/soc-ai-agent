from pydantic import BaseModel
from datetime import datetime

class SystemLogCreate(BaseModel):
    source_ip: str
    event_type: str
    description: str

class SystemLogResponse(SystemLogCreate):
    id: int
    timestamp: datetime
    is_malicious: bool
    threat_type: str
    severity: str
    reasoning: str

    class Config:
        from_attributes = True