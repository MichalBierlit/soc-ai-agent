"""
mitre_engine.py – Moduł mapowania MITRE ATT&CK i Threat Hunting (Text-to-SQL)
dla SOC AI Threat Intelligence Platform.
"""

import os
import re

import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()


# ---------------------------------------------------------------------------
# CZĘŚĆ 1: MITRE ATT&CK
# ---------------------------------------------------------------------------

MITRE_MAPPING: dict[str, dict] = {
    "Brute Force": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique": "Brute Force",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "Port Scan": {
        "tactic": "Reconnaissance",
        "technique_id": "T1046",
        "technique": "Network Service Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "SQL Injection": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing App",
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "XSS": {
        "tactic": "Execution",
        "technique_id": "T1059.007",
        "technique": "JavaScript Execution",
        "url": "https://attack.mitre.org/techniques/T1059/007/",
    },
    "Command Injection": {
        "tactic": "Execution",
        "technique_id": "T1059",
        "technique": "Command and Scripting Interpreter",
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    "DDoS": {
        "tactic": "Impact",
        "technique_id": "T1498",
        "technique": "Network Denial of Service",
        "url": "https://attack.mitre.org/techniques/T1498/",
    },
    "Malware": {
        "tactic": "Execution",
        "technique_id": "T1204",
        "technique": "User Execution",
        "url": "https://attack.mitre.org/techniques/T1204/",
    },
    "Ransomware": {
        "tactic": "Impact",
        "technique_id": "T1486",
        "technique": "Data Encrypted for Impact",
        "url": "https://attack.mitre.org/techniques/T1486/",
    },
    "Lateral Movement": {
        "tactic": "Lateral Movement",
        "technique_id": "T1021",
        "technique": "Remote Services",
        "url": "https://attack.mitre.org/techniques/T1021/",
    },
    "Privilege Escalation": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1068",
        "technique": "Exploitation for Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1068/",
    },
    "Exfiltration": {
        "tactic": "Exfiltration",
        "technique_id": "T1041",
        "technique": "Exfiltration Over C2 Channel",
        "url": "https://attack.mitre.org/techniques/T1041/",
    },
    "Phishing": {
        "tactic": "Initial Access",
        "technique_id": "T1566",
        "technique": "Phishing",
        "url": "https://attack.mitre.org/techniques/T1566/",
    },
    "C2 Beacon": {
        "tactic": "Command and Control",
        "technique_id": "T1071",
        "technique": "Application Layer Protocol",
        "url": "https://attack.mitre.org/techniques/T1071/",
    },
    "Anomaly": {
        "tactic": "Discovery",
        "technique_id": "T1082",
        "technique": "System Information Discovery",
        "url": "https://attack.mitre.org/techniques/T1082/",
    },
}

_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

_DANGEROUS_KEYWORDS = re.compile(
    r"\b(DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE)\b", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Funkcja 1
# ---------------------------------------------------------------------------

def classify_event_mitre(threat_type: str) -> dict:
    """
    Klasyfikuje zdarzenie według MITRE ATT&CK na podstawie threat_type.

    Wyszukiwanie jest case-insensitive i dopuszcza częściowe dopasowanie
    (threat_type może być podciągiem klucza lub klucz podciągiem threat_type).

    Parametry
    ---------
    threat_type : str
        Typ zagrożenia pobrany z bazy danych.

    Zwraca
    ------
    dict
        Słownik z kluczami: tactic, technique_id, technique, url.
    """
    if not threat_type or not isinstance(threat_type, str):
        return {
            "tactic": "Unknown",
            "technique_id": "T????",
            "technique": str(threat_type),
            "url": "https://attack.mitre.org/",
        }

    needle = threat_type.strip().lower()

    # Dokładne dopasowanie (case-insensitive)
    for key, value in MITRE_MAPPING.items():
        if key.lower() == needle:
            return value

    # Częściowe dopasowanie
    for key, value in MITRE_MAPPING.items():
        if needle in key.lower() or key.lower() in needle:
            return value

    # Fallback
    return {
        "tactic": "Unknown",
        "technique_id": "T????",
        "technique": threat_type,
        "url": "https://attack.mitre.org/",
    }


# ---------------------------------------------------------------------------
# Funkcja 2
# ---------------------------------------------------------------------------

def enrich_dataframe_with_mitre(df: pd.DataFrame) -> pd.DataFrame:
    """
    Wzbogaca DataFrame o kolumny MITRE ATT&CK.

    Na podstawie kolumny `threat_type` dodaje:
    - mitre_tactic
    - mitre_technique_id
    - mitre_technique
    - mitre_url

    Parametry
    ---------
    df : pd.DataFrame
        DataFrame zawierający przynajmniej kolumnę `threat_type`.

    Zwraca
    ------
    pd.DataFrame
        Nowy DataFrame z dodatkowymi kolumnami (oryginał nie jest modyfikowany).
    """
    if df is None or df.empty:
        return df.copy() if df is not None else pd.DataFrame()

    result = df.copy()

    if "threat_type" not in result.columns:
        for col in ("mitre_tactic", "mitre_technique_id", "mitre_technique", "mitre_url"):
            result[col] = "N/A"
        return result

    classifications = result["threat_type"].apply(classify_event_mitre)
    result["mitre_tactic"] = classifications.apply(lambda x: x["tactic"])
    result["mitre_technique_id"] = classifications.apply(lambda x: x["technique_id"])
    result["mitre_technique"] = classifications.apply(lambda x: x["technique"])
    result["mitre_url"] = classifications.apply(lambda x: x["url"])

    return result


# ---------------------------------------------------------------------------
# Funkcja 3
# ---------------------------------------------------------------------------

def get_mitre_heatmap_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Generuje dane do heatmapy MITRE ATT&CK.

    Grupuje zdarzenia według taktyki i techniki, zlicza wystąpienia
    i wyznacza maksymalną dotkliwość (severity) w grupie.

    Parametry
    ---------
    df : pd.DataFrame
        DataFrame z kolumnami MITRE (wzbogacony przez enrich_dataframe_with_mitre).

    Zwraca
    ------
    pd.DataFrame
        DataFrame z kolumnami: Tactic, Technique, TechniqueID, Count, Severity_Max.
        Posortowany malejąco po Count.
    """
    required = {"mitre_tactic", "mitre_technique_id", "mitre_technique"}
    if df is None or df.empty or not required.issubset(df.columns):
        return pd.DataFrame(columns=["Tactic", "Technique", "TechniqueID", "Count", "Severity_Max"])

    work = df.copy()

    if "severity" in work.columns:
        work["_sev_num"] = work["severity"].str.lower().map(_SEVERITY_ORDER).fillna(0).astype(int)
    else:
        work["_sev_num"] = 0

    grouped = (
        work.groupby(["mitre_tactic", "mitre_technique", "mitre_technique_id"], as_index=False)
        .agg(Count=("mitre_tactic", "count"), _sev_max=("_sev_num", "max"))
    )

    # Konwersja z powrotem na etykietę severity
    sev_reverse = {v: k for k, v in _SEVERITY_ORDER.items()}
    grouped["Severity_Max"] = grouped["_sev_max"].map(sev_reverse).fillna("unknown")

    result = grouped.rename(
        columns={
            "mitre_tactic": "Tactic",
            "mitre_technique": "Technique",
            "mitre_technique_id": "TechniqueID",
        }
    )[["Tactic", "Technique", "TechniqueID", "Count", "Severity_Max"]]

    return result.sort_values("Count", ascending=False).reset_index(drop=True)


# ---------------------------------------------------------------------------
# CZĘŚĆ 2: Text-to-SQL (Threat Hunting)
# ---------------------------------------------------------------------------

_GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

def get_groq_model() -> str:
    return os.getenv("GROQ_MODEL", "qwen/qwen3.8-27b")


_SQL_SYSTEM_PROMPT = (
    "Jesteś ekspertem SQL dla bazy PostgreSQL SOC. "
    "Tabela: `analyzed_logs` z kolumnami: "
    "id (int), timestamp (timestamptz), source_ip (varchar), "
    "event_type (varchar), is_malicious (bool), threat_type (varchar), "
    "severity (varchar - wartości: 'low','medium','high','critical'), "
    "reasoning (text). "
    "Wygeneruj TYLKO i WYŁĄCZNIE zapytanie SQL SELECT "
    "(bez wyjaśnień, bez markdown, bez ```sql)."
)


# ---------------------------------------------------------------------------
# Funkcja 4
# ---------------------------------------------------------------------------

def natural_language_to_sql(question: str) -> str:
    """
    Przekształca pytanie w języku naturalnym na zapytanie SQL (Text-to-SQL).

    Używa modelu Groq (qwen/qwen3.8-27b) z dedykowanym promptem
    systemowym dla bazy SOC. Odpowiedź jest czyszczona z bloków markdown
    i walidowana pod kątem poprawności składniowej (SELECT … FROM analyzed_logs).

    Parametry
    ---------
    question : str
        Pytanie dotyczące logów bezpieczeństwa.

    Zwraca
    ------
    str
        Gotowe do wykonania zapytanie SQL SELECT.

    Raises
    ------
    ValueError
        Gdy wygenerowane zapytanie nie spełnia wymogów bezpieczeństwa/poprawności.
    RuntimeError
        Gdy wywołanie API zakończy się błędem.
    """
    api_key = os.getenv("GROQ_API_KEY", "")
    if not api_key:
        raise RuntimeError("Brak klucza GROQ_API_KEY w zmiennych środowiskowych.")

    payload = {
        "model": get_groq_model(),
        "messages": [
            {"role": "system", "content": _SQL_SYSTEM_PROMPT},
            {"role": "user", "content": f"Pytanie: {question}"},
        ],
        "temperature": 0.3,
        "max_tokens": 512,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.post(_GROQ_URL, json=payload, headers=headers, timeout=30)
        response.raise_for_status()
    except requests.exceptions.Timeout:
        raise RuntimeError("Przekroczono czas oczekiwania na odpowiedź Groq API (30s).")
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"Błąd komunikacji z Groq API: {exc}") from exc

    data = response.json()
    raw_sql: str = data["choices"][0]["message"]["content"].strip()

    # Czyszczenie odpowiedzi z bloków markdown
    raw_sql = re.sub(r"```sql", "", raw_sql, flags=re.IGNORECASE)
    raw_sql = re.sub(r"```", "", raw_sql)
    sql = raw_sql.strip()

    # Walidacja: musi zawierać SELECT i FROM analyzed_logs
    if not re.search(r"\bSELECT\b", sql, re.IGNORECASE):
        raise ValueError(f"Wygenerowane zapytanie nie zawiera SELECT:\n{sql}")
    if not re.search(r"\bFROM\s+analyzed_logs\b", sql, re.IGNORECASE):
        raise ValueError(
            f"Wygenerowane zapytanie nie odwołuje się do tabeli analyzed_logs:\n{sql}"
        )

    return sql


# ---------------------------------------------------------------------------
# Funkcja 5
# ---------------------------------------------------------------------------

def execute_hunt_query(sql: str, engine) -> pd.DataFrame:
    """
    Wykonuje zapytanie SQL na silniku SQLAlchemy i zwraca wyniki jako DataFrame.

    Automatycznie dodaje LIMIT 500 jeśli zapytanie nie zawiera klauzuli LIMIT.
    Blokuje niebezpieczne zapytania modyfikujące dane (DROP, DELETE, UPDATE itd.).

    Parametry
    ---------
    sql : str
        Zapytanie SELECT do wykonania.
    engine :
        Silnik SQLAlchemy (np. zwrócony przez create_engine).

    Zwraca
    ------
    pd.DataFrame
        Wyniki zapytania.

    Raises
    ------
    ValueError
        Gdy zapytanie zawiera niebezpieczne słowa kluczowe lub silnik jest None.
    """
    if engine is None:
        raise ValueError("Brak połączenia z bazą danych (engine is None).")

    # Blokada niebezpiecznych operacji
    if _DANGEROUS_KEYWORDS.search(sql):
        raise ValueError(
            "Zapytanie zawiera niedozwolone słowo kluczowe "
            "(DROP/DELETE/UPDATE/INSERT/ALTER/TRUNCATE). Operacja zablokowana."
        )

    # Dodaj LIMIT jeśli brak
    if not re.search(r"\bLIMIT\b", sql, re.IGNORECASE):
        sql = sql.rstrip("; \t\n") + " LIMIT 500"

    return pd.read_sql(sql, engine)


# ---------------------------------------------------------------------------
# CZĘŚĆ 3: Interfejs Streamlit
# ---------------------------------------------------------------------------

def render_mitre_tab(df: pd.DataFrame, engine=None) -> None:
    """
    Renderuje zakładkę MITRE ATT&CK w aplikacji Streamlit.

    Składa się z dwóch sekcji:
    1. Klasyfikacja MITRE ATT&CK – tabela wzbogacona o taktyki/techniki
       oraz heatmapa i wykres słupkowy.
    2. Threat Hunting (Text-to-SQL) – interfejs do zadawania pytań
       w języku naturalnym i przeglądania wyników SQL.

    Parametry
    ---------
    df : pd.DataFrame
        DataFrame z logami bezpieczeństwa (wynik load_data()).
    engine : optional
        Silnik SQLAlchemy do wykonywania zapytań threat hunting.
    """
    st.header("🛡️ MITRE ATT&CK & Threat Hunting")

    # ------------------------------------------------------------------ #
    # Sekcja 1: Klasyfikacja MITRE ATT&CK
    # ------------------------------------------------------------------ #
    st.subheader("🎯 Klasyfikacja MITRE ATT&CK")

    if df is None or df.empty:
        st.info("Brak danych do wyświetlenia.")
    else:
        # Filtruj tylko złośliwe zdarzenia
        malicious_df = df[df["is_malicious"] == True].copy() if "is_malicious" in df.columns else df.copy()

        if malicious_df.empty:
            st.info("Brak złośliwych zdarzeń w danych.")
        else:
            enriched = enrich_dataframe_with_mitre(malicious_df)

            # Tabela z kolumnami MITRE
            display_cols = [c for c in ["source_ip", "threat_type", "mitre_tactic",
                                         "mitre_technique_id", "mitre_technique", "mitre_url"]
                            if c in enriched.columns]

            st.markdown("**Zdarzenia złośliwe z klasyfikacją MITRE ATT&CK**")
            st.dataframe(
                enriched[display_cols],
                column_config={
                    "mitre_url": st.column_config.LinkColumn("🔗 Link MITRE", display_text="ATT&CK ↗"),
                },
                use_container_width=True,
                hide_index=True,
            )

            # Heatmapa taktyk/technik
            st.markdown("**Heatmapa taktyk i technik MITRE ATT&CK**")
            heatmap_df = get_mitre_heatmap_data(enriched)

            if not heatmap_df.empty:
                max_count = int(heatmap_df["Count"].max()) if not heatmap_df.empty else 1
                st.dataframe(
                    heatmap_df,
                    column_config={
                        "Count": st.column_config.ProgressColumn(
                            "Count",
                            help="Liczba zdarzeń (im szersszy pasek, tym więcej)",
                            format="%d",
                            min_value=0,
                            max_value=max_count,
                        ),
                        "Severity_Max": st.column_config.TextColumn("Maks. Severity"),
                    },
                    use_container_width=True,
                    hide_index=True,
                )

                # Wykres słupkowy: zdarzenia per Tactic
                st.markdown("**Liczba zdarzeń według taktyki MITRE ATT&CK**")
                tactic_counts = (
                    heatmap_df.groupby("Tactic")["Count"]
                    .sum()
                    .sort_values(ascending=False)
                )
                st.bar_chart(tactic_counts)
            else:
                st.info("Brak danych do wyświetlenia heatmapy.")

    st.divider()

    # ------------------------------------------------------------------ #
    # Sekcja 2: Threat Hunting (Text-to-SQL)
    # ------------------------------------------------------------------ #
    st.subheader("🔍 Threat Hunting (Text-to-SQL)")

    if engine is None:
        st.warning("⚠️ Brak połączenia z bazą danych. Threat Hunting jest niedostępny.")
        return

    question = st.text_input(
        "Zadaj pytanie o logi (np. 'Pokaż 10 najgroźniejszych IP z ostatnich 24h'):",
        placeholder="Wpisz pytanie w języku naturalnym...",
        key="hunt_question",
    )

    if st.button("🔍 Szukaj", key="hunt_search"):
        if not question.strip():
            st.warning("Wpisz pytanie przed wyszukiwaniem.")
            return

        with st.spinner("Generowanie zapytania SQL przez AI..."):
            try:
                sql_query = natural_language_to_sql(question)
            except (ValueError, RuntimeError) as exc:
                st.error(f"❌ Błąd generowania SQL: {exc}")
                return
            except Exception as exc:
                st.error(f"❌ Nieoczekiwany błąd: {exc}")
                return

        st.markdown("**Wygenerowane zapytanie SQL:**")
        st.code(sql_query, language="sql")

        with st.spinner("Wykonywanie zapytania..."):
            try:
                results = execute_hunt_query(sql_query, engine)
            except ValueError as exc:
                st.error(f"❌ Błąd wykonania zapytania: {exc}")
                return
            except Exception as exc:
                st.error(f"❌ Nieoczekiwany błąd podczas wykonywania zapytania: {exc}")
                return

        if results.empty:
            st.info("Zapytanie wykonane poprawnie, lecz nie zwróciło żadnych wyników.")
        else:
            st.success(f"✅ Znaleziono {len(results)} rekordów.")
            st.dataframe(results, use_container_width=True, hide_index=True)
