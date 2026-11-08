import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field

# Wczytanie klucza API z pliku .env
load_dotenv()

# Struktura JSON, której oczekujemy od AI
class SecurityAnalysis(BaseModel):
    is_malicious: bool = Field(description="Czy log wskazuje na złośliwe działanie?")
    threat_type: str = Field(description="Kategoria ataku (np. Brute Force, SQL Injection, Brak)")
    severity: str = Field(description="Poziom zagrożenia: Low, Medium, High, Critical, None")
    reasoning: str = Field(description="Krótkie, jednozdaniowe uzasadnienie decyzji")

# Prompt systemowy (nadanie roli)
prompt = ChatPromptTemplate.from_messages([
    ("system", "Jesteś analitykiem Security Operations Center (SOC). Otrzymujesz logi systemowe. Twoim zadaniem jest precyzyjna kategoryzacja zagrożeń."),
    ("human", "Przeanalizuj log:\nIP Źródłowe: {source_ip}\nZdarzenie: {event_type}\nOpis: {description}")
])

def get_agent_chain():
    """Tworzy łańcuch wykonawczy z bezpieczną weryfikacją klucza API."""
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key or not api_key.strip():
        return None
    
    try:
        model = os.getenv("GROQ_MODEL", "qwen/qwen3.8-27b")
        llm = ChatGroq(
            groq_api_key=api_key.strip(),
            model_name=model,
            temperature=0
        )
        structured_llm = llm.with_structured_output(SecurityAnalysis)
        return prompt | structured_llm
    except Exception as e:
        print(f"⚠️ Błąd inicjalizacji ChatGroq: {e}")
        return None

def analyze_log(source_ip: str, event_type: str, description: str) -> SecurityAnalysis:
    chain = get_agent_chain()
    if not chain:
        return SecurityAnalysis(
            is_malicious=False,
            threat_type="Unclassified",
            severity="low",
            reasoning="Brak aktywnego klucza GROQ_API_KEY w pliku .env — pominięto analizę AI."
        )
    try:
        return chain.invoke({
            "source_ip": source_ip,
            "event_type": event_type,
            "description": description
        })
    except Exception as e:
        return SecurityAnalysis(
            is_malicious=False,
            threat_type="Error",
            severity="low",
            reasoning=f"Błąd podczas wywołania AI: {e}"
        )
