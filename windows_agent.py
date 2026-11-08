import os
import subprocess
import json
import requests
import time
from dotenv import load_dotenv

load_dotenv()

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000/analyze-and-save/")

def get_recent_windows_logs(count=3):
    # Próba 1: Pobranie z Microsoft-Windows-Sysmon/Operational
    ps_command_sysmon = (
        f'Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents {count} | '
        "Select-Object Id, Message | ConvertTo-Json -Compress"
    )
    
    result = subprocess.run(
        ["powershell", "-Command", ps_command_sysmon], 
        capture_output=True, 
        text=True, 
        errors="ignore"
    )
    
    # Fallback: Jeśli Sysmon nie jest zainstalowany lub brak uprawnień, pobierz ze standardowego dziennika System
    if result.returncode != 0:
        ps_command_system = (
            f'Get-WinEvent -LogName "System" -MaxEvents {count} | '
            "Select-Object Id, Message | ConvertTo-Json -Compress"
        )
        result = subprocess.run(
            ["powershell", "-Command", ps_command_system], 
            capture_output=True, 
            text=True, 
            errors="ignore"
        )

    if result.returncode != 0:
        print("Błąd dostępu do logów Windows. Upewnij się, że terminal ma odpowiednie uprawnienia.")
        return []

    try:
        logs = json.loads(result.stdout)
        # PowerShell zwraca pojedynczy obiekt jeśli count=1, w przeciwnym razie listę
        return [logs] if isinstance(logs, dict) else logs
    except json.JSONDecodeError:
        print("Nie udało się zdekodować odpowiedzi od systemu.")
        return []

if __name__ == "__main__":
    print("🕵️ Uruchamianie agenta nasłuchującego dla Windows...\n")
    
    # Pobieramy 20 logów
    events = get_recent_windows_logs(20)
    
    for idx, event in enumerate(events, 1):
        event_id = event.get("Id", "UNKNOWN")
        # Bezpieczna obsługa Message (nawet jeśli Message jest None)
        raw_message = event.get("Message") or "Brak opisu"
        raw_message_str = str(raw_message)
        description = raw_message_str[:500] + "..." if len(raw_message_str) > 500 else raw_message_str

        payload = {
            "source_ip": "127.0.0.1",
            "event_type": f"WIN_EVENT_{event_id}",
            "description": description.replace("\n", " ").strip()
        }
        
        print(f"[{idx}/{len(events)}] Przesyłanie zdarzenia WIN_EVENT_{event_id} do bazy SOC...")
        
        try:
            response = requests.post(API_URL, json=payload, timeout=10)
            if response.status_code == 200:
                result = response.json()
                print(f" └─ AI: Złośliwe? {result['is_malicious']} | Werdykt: {result['threat_type']} ({result['severity']})")
                print(f" └─ Uzasadnienie: {result['reasoning']}\n")
            else:
                print(f" └─ Błąd zapisu w API: HTTP {response.status_code}\n")
        except Exception as e:
            print(f" └─ Krytyczny błąd połączenia: {e}\n")
            
        time.sleep(2)  # Krótka pauza, aby nie uderzyć w limit zapytań (Rate Limit) API
