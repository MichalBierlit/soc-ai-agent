"""
modules/soar_engine.py
----------------------
Moduł SOAR (Security Orchestration, Automation and Response) – Etap 2.1
Odpowiada za:
  1. Generowanie reguł blokujących dla Windows Firewall (netsh) i Linux iptables.
  2. Generowanie interaktywnych Playbooków Incident Response za pomocą AI (Groq / Qwen).
"""

import os
import re
import requests
import streamlit as st
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()



# ─────────────────────────────────────────────
#  SEKCJA 1: Generatory reguł Firewall
# ─────────────────────────────────────────────

def generate_windows_firewall_rules(malicious_ips: list[str]) -> str:
    """
    Generuje zestaw poleceń `netsh advfirewall` blokujących podane IP
    zarówno dla ruchu przychodzącego, jak i wychodzącego.

    Args:
        malicious_ips: Lista złośliwych adresów IP do zablokowania.

    Returns:
        Gotowy skrypt .bat jako string.
    """
    if not malicious_ips:
        return ":: Brak złośliwych adresów IP do zablokowania."

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "@echo off",
        f":: Automatycznie wygenerowany skrypt blokujący – SOC AI Agent",
        f":: Data generacji: {timestamp}",
        f":: Liczba blokowanych adresów IP: {len(malicious_ips)}",
        "",
        "echo [*] Dodawanie reguł Windows Firewall...",
        "",
    ]

    for ip in malicious_ips:
        # Sanityzacja – akceptujemy tylko poprawne formaty IPv4/IPv6
        if not _is_valid_ip(ip):
            lines.append(f":: POMINIĘTO (nieprawidłowy format): {ip}")
            continue

        safe_ip = ip.replace(":", "_")  # dla IPv6 w nazwie reguły
        rule_name_in  = f"SOC-BLOCK-IN-{safe_ip}"
        rule_name_out = f"SOC-BLOCK-OUT-{safe_ip}"

        lines.append(f":: Blokowanie: {ip}")
        lines.append(
            f'netsh advfirewall firewall add rule name="{rule_name_in}" '
            f'dir=in action=block remoteip={ip} enable=yes'
        )
        lines.append(
            f'netsh advfirewall firewall add rule name="{rule_name_out}" '
            f'dir=out action=block remoteip={ip} enable=yes'
        )
        lines.append("")

    lines.append("echo [+] Gotowe. Reguły zostały dodane.")
    lines.append("pause")
    return "\n".join(lines)


def generate_linux_iptables_rules(malicious_ips: list[str]) -> str:
    """
    Generuje skrypt bash z regułami iptables DROP dla podanych IP.

    Args:
        malicious_ips: Lista złośliwych adresów IP do zablokowania.

    Returns:
        Gotowy skrypt .sh jako string.
    """
    if not malicious_ips:
        return "# Brak złośliwych adresów IP do zablokowania."

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "#!/bin/bash",
        f"# Automatycznie wygenerowany skrypt blokujący – SOC AI Agent",
        f"# Data generacji: {timestamp}",
        f"# Liczba blokowanych adresów IP: {len(malicious_ips)}",
        "",
        'echo "[*] Dodawanie reguł iptables..."',
        "",
    ]

    for ip in malicious_ips:
        if not _is_valid_ip(ip):
            lines.append(f"# POMINIĘTO (nieprawidłowy format): {ip}")
            continue

        lines.append(f"# Blokowanie: {ip}")
        lines.append(f"iptables -A INPUT  -s {ip} -j DROP")
        lines.append(f"iptables -A OUTPUT -d {ip} -j DROP")
        lines.append(f"iptables -A FORWARD -s {ip} -j DROP")
        lines.append("")

    lines += [
        'echo "[+] Gotowe. Reguły zostały dodane."',
        "",
        "# Aby utrwalić reguły po restarcie (Debian/Ubuntu):",
        "# iptables-save > /etc/iptables/rules.v4",
        "",
        "# Aby utrwalić reguły po restarcie (RHEL/CentOS):",
        "# service iptables save",
    ]
    return "\n".join(lines)


def _is_valid_ip(ip: str) -> bool:
    """Prosta walidacja formatu IPv4 lub IPv6."""
    ipv4_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    ipv6_pattern = re.compile(
        r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"
    )
    return bool(ipv4_pattern.match(ip) or ipv6_pattern.match(ip))


# ─────────────────────────────────────────────
#  SEKCJA 2: Generator Playbooków AI (Groq/Qwen)
# ─────────────────────────────────────────────

# Predefiniowane szablony typów incydentów – wspomagają prompt
INCIDENT_TEMPLATES = {
    "Nieznany / Ogólny": "generyczny incydent bezpieczeństwa",
    "Atak Brute-Force / Credential Stuffing": "brute-force lub credential stuffing na konta użytkowników",
    "Infekcja Malware / Ransomware": "infekcja złośliwym oprogramowaniem lub ransomware",
    "Eksfiltracja Danych (Data Breach)": "eksfiltracja poufnych danych z sieci firmowej",
    "Phishing / BEC (Business Email Compromise)": "atak phishingowy lub kompromitacja poczty firmowej (BEC)",
    "Atak DDoS": "atak typu Distributed Denial of Service (DDoS)",
    "Zagrożenie wewnętrzne (Insider Threat)": "nieautoryzowana aktywność pracownika lub złośliwego insidera",
    "Eskalacja uprawnień / Lateral Movement": "eskalacja uprawnień lub poruszanie się po sieci (lateral movement)",
    "Podatność / Exploit (CVE)": "wykorzystanie podatności CVE / zdalny exploit",
    "Anomalia w ruchu sieciowym": "podejrzana anomalia w ruchu sieciowym wykryta przez IDS/IPS",
}


def generate_playbook_with_ai(
    incident_type: str,
    malicious_ips: list[str],
    extra_context: str = "",
) -> str:
    """
    Wysyła zapytanie do API Groq (model Qwen) i zwraca gotowy Playbook IR.

    Args:
        incident_type:   Rodzaj incydentu wybrany przez analityka.
        malicious_ips:   Lista zidentyfikowanych złośliwych IP (opcjonalna).
        extra_context:   Dodatkowy kontekst wpisany przez analityka.

    Returns:
        Playbook jako sformatowany string (Markdown).
    """
    groq_key_raw = os.getenv("GROQ_API_KEY")
    if not groq_key_raw:
        return "❌ **Błąd:** Brak klucza `GROQ_API_KEY` w pliku `.env`."

    groq_key = groq_key_raw.strip()
    ip_list_str = ", ".join(malicious_ips) if malicious_ips else "Brak zidentyfikowanych IP"
    incident_desc = INCIDENT_TEMPLATES.get(incident_type, incident_type)

    prompt = (
        "Jesteś starszym analitykiem SOC i ekspertem od Incident Response (IR). "
        f"Zostałeś wezwany do obsługi incydentu bezpieczeństwa: **{incident_desc}**.\n\n"
        f"Zidentyfikowane złośliwe adresy IP: {ip_list_str}.\n"
    )

    if extra_context.strip():
        prompt += f"Dodatkowy kontekst od analityka: {extra_context.strip()}\n\n"

    prompt += (
        "Wygeneruj kompletny, numerowany **Playbook Incident Response** w języku polskim, "
        "podzielony na pięć faz:\n"
        "1. **Identyfikacja i Triage** – jak potwierdzić incydent i ocenić jego zakres.\n"
        "2. **Powstrzymanie (Containment)** – natychmiastowe akcje izolacyjne.\n"
        "3. **Eliminacja (Eradication)** – usunięcie zagrożenia z infrastruktury.\n"
        "4. **Odtworzenie (Recovery)** – bezpieczny powrót do operacji.\n"
        "5. **Wnioski (Lessons Learned)** – dokumentacja, raport i ulepszenie procedur.\n\n"
        "Każdy krok powinien zawierać konkretne, wykonalne polecenia lub działania. "
        "Formatuj odpowiedź w Markdown (nagłówki, listy numerowane, pogrubienia)."
    )

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {groq_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": os.getenv("GROQ_MODEL", "qwen/qwen3.8-27b"),
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.4,
        "max_tokens": 2048,
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"].strip()
        else:
            return f"❌ **Błąd API Groq** ({response.status_code}):\n```\n{response.text}\n```"
    except Exception as e:
        return f"❌ **Błąd połączenia z Groq:** {e}"


# ─────────────────────────────────────────────
#  SEKCJA 3: Interfejs Streamlit (renderowany przez dashboard.py)
# ─────────────────────────────────────────────

def render_soar_tab(malicious_ips_from_context: list[str] | None = None):
    """
    Renderuje pełną zakładkę SOAR w aplikacji Streamlit.

    Wywołaj tę funkcję wewnątrz bloku `with tab_soar:` w dashboard.py.

    Args:
        malicious_ips_from_context: Opcjonalna lista złośliwych IP przekazana
                                    z innych zakładek (np. z analizy PCAP).
    """
    st.header("⚡ SOAR – Automatyczna Odpowiedź na Incydenty")
    st.write(
        "Generuj gotowe reguły blokujące dla firewalli oraz interaktywne "
        "**Playbooki Incident Response** wspomagane przez AI (Qwen)."
    )

    # ── Panel 1: Zarządzanie IP ──────────────────────────────────────────
    st.subheader("🎯 Złośliwe Adresy IP")

    col_ip, col_info = st.columns([3, 1])
    with col_ip:
        default_ips = "\n".join(malicious_ips_from_context) if malicious_ips_from_context else ""
        raw_ips = st.text_area(
            "Wpisz złośliwe adresy IP (jeden na linię):",
            value=default_ips,
            height=120,
            placeholder="1.2.3.4\n5.6.7.8\n192.168.0.100",
            help="Adresy IP zostaną użyte do generowania reguł firewall i kontekstu playbooków.",
        )
    with col_info:
        st.metric("Załadowanych IP", len(malicious_ips_from_context) if malicious_ips_from_context else 0,
                  help="IP przekazane automatycznie z analizy PCAP/Sysmon")

    # Parsuj i waliduj listę IP z pola tekstowego
    ip_lines = [line.strip() for line in raw_ips.splitlines() if line.strip()]
    valid_ips   = [ip for ip in ip_lines if _is_valid_ip(ip)]
    invalid_ips = [ip for ip in ip_lines if not _is_valid_ip(ip)]

    if valid_ips:
        st.success(f"✅ Poprawnych adresów IP: **{len(valid_ips)}**")
    if invalid_ips:
        st.warning(f"⚠️ Pominięto {len(invalid_ips)} nieprawidłowych wpisów: `{', '.join(invalid_ips)}`")

    st.markdown("---")

    # ── Panel 2: Generator Reguł Firewall ───────────────────────────────
    st.subheader("🛡️ Generator Reguł Firewall")

    fw_col1, fw_col2 = st.columns(2)

    with fw_col1:
        st.markdown("#### 🪟 Windows Firewall (netsh)")
        if st.button("Generuj reguły Windows (.bat)", use_container_width=True):
            bat_script = generate_windows_firewall_rules(valid_ips)
            st.session_state["win_fw_script"] = bat_script

        if "win_fw_script" in st.session_state:
            st.code(st.session_state["win_fw_script"], language="batch")
            st.download_button(
                label="📥 Pobierz skrypt .bat",
                data=st.session_state["win_fw_script"],
                file_name=f"soc_block_windows_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bat",
                mime="text/plain",
                use_container_width=True,
            )

    with fw_col2:
        st.markdown("#### 🐧 Linux iptables")
        if st.button("Generuj reguły Linux (.sh)", use_container_width=True):
            sh_script = generate_linux_iptables_rules(valid_ips)
            st.session_state["linux_fw_script"] = sh_script

        if "linux_fw_script" in st.session_state:
            st.code(st.session_state["linux_fw_script"], language="bash")
            st.download_button(
                label="📥 Pobierz skrypt .sh",
                data=st.session_state["linux_fw_script"],
                file_name=f"soc_block_linux_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sh",
                mime="text/plain",
                use_container_width=True,
            )

    st.markdown("---")

    # ── Panel 3: Generator Playbooków AI ────────────────────────────────
    st.subheader("🤖 Generator Playbooków Incident Response (AI)")
    st.write("AI wygeneruje szczegółowy, krok-po-kroku Playbook dopasowany do Twojego incydentu.")

    pb_col1, pb_col2 = st.columns([2, 1])
    with pb_col1:
        incident_type = st.selectbox(
            "Wybierz typ incydentu:",
            options=list(INCIDENT_TEMPLATES.keys()),
            index=0,
        )
    with pb_col2:
        st.metric("Model AI", "Qwen 3-8B (Groq)")

    extra_context = st.text_area(
        "Dodatkowy kontekst (opcjonalnie):",
        height=80,
        placeholder="np. Zaatakowany host: WIN-SERVER-01, port 443, wykryto beaconing co 30s...",
    )

    if st.button("🚀 Generuj Playbook IR", type="primary", use_container_width=True):
        if not os.getenv("GROQ_API_KEY"):
            st.error("Brak klucza GROQ_API_KEY w pliku .env – nie można wywołać AI.")
        else:
            with st.spinner("🤖 AI analizuje incydent i tworzy Playbook..."):
                playbook = generate_playbook_with_ai(
                    incident_type=incident_type,
                    malicious_ips=valid_ips,
                    extra_context=extra_context,
                )
                st.session_state["last_playbook"] = playbook
                st.session_state["last_playbook_type"] = incident_type

    if "last_playbook" in st.session_state:
        st.markdown("---")
        st.subheader(f"📋 Playbook: {st.session_state.get('last_playbook_type', '')}")
        st.markdown(st.session_state["last_playbook"])

        st.download_button(
            label="📥 Pobierz Playbook (.md)",
            data=st.session_state["last_playbook"],
            file_name=f"playbook_IR_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            mime="text/markdown",
            use_container_width=True,
        )

