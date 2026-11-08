"""
discord_notifier.py — Moduł do wysyłania alertów bezpieczeństwa na Discord
przez Webhook. Część platformy SOC AI Threat Intelligence.
"""

import requests
import time
import os
import json
import streamlit as st
import pandas as pd

# ── Kolory embedów Discord wg poziomu zagrożenia ──────────────────────────────
SEVERITY_COLORS = {
    "critical": 0xFF0000,  # czerwony
    "high":     0xFF6600,  # pomarańczowy
    "medium":   0xFFAA00,  # żółty
    "low":      0x0099FF,  # niebieski
    "info":     0x00FF00,  # zielony
}

# Emoji przypisane do severity
SEVERITY_EMOJI = {
    "critical": "🚨",
    "high":     "🔴",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "ℹ️",
}

DISCORD_WEBHOOK_PREFIX = "https://discord.com/api/webhooks/"


# ── Walidacja Webhook URL ─────────────────────────────────────────────────────

def _validate_webhook_url(webhook_url: str) -> bool:
    """Sprawdza czy podany URL jest prawidłowym Discord Webhook URL."""
    if not webhook_url:
        return False
    return webhook_url.strip().startswith(DISCORD_WEBHOOK_PREFIX)


# ── Funkcja 1: Wysyłanie pojedynczego alertu ──────────────────────────────────

def send_discord_alert(webhook_url: str, event_data: dict) -> tuple[bool, str]:
    """
    Wysyła Rich Embed z alertem bezpieczeństwa na Discord przez Webhook.

    Parametry:
        webhook_url (str): URL Discord Webhooka.
        event_data (dict): Słownik ze zdarzeniem. Oczekiwane klucze:
            - source_ip   (str)
            - event_type  (str)
            - threat_type (str)
            - severity    (str)  — 'critical' / 'high' / 'medium' / 'low' / 'info'
            - reasoning   (str)
            - timestamp   (str)

    Zwraca:
        tuple[bool, str]: (sukces, komunikat opisowy)
    """
    if not _validate_webhook_url(webhook_url):
        return False, "Nieprawidłowy URL Webhooka. Musi zaczynać się od https://discord.com/api/webhooks/"

    # Normalizacja severity do małych liter
    severity = str(event_data.get("severity", "info")).lower()
    color    = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["info"])
    emoji    = SEVERITY_EMOJI.get(severity, "ℹ️")

    # Skróć reasoning jeśli jest za długi (limit pola Embeda: 1024 znaki)
    reasoning = str(event_data.get("reasoning", "Brak analizy"))
    if len(reasoning) > 1000:
        reasoning = reasoning[:997] + "..."

    embed = {
        "title": f"{emoji} SOC ALERT — {severity.upper()}",
        "color": color,
        "fields": [
            {
                "name": "🌐 Źródłowy IP",
                "value": str(event_data.get("source_ip", "N/A")),
                "inline": True,
            },
            {
                "name": "📋 Typ zdarzenia",
                "value": str(event_data.get("event_type", "N/A")),
                "inline": True,
            },
            {
                "name": "☣️ Typ zagrożenia",
                "value": str(event_data.get("threat_type", "N/A")),
                "inline": True,
            },
            {
                "name": "🧠 Analiza AI",
                "value": reasoning,
                "inline": False,
            },
        ],
        "timestamp": str(event_data.get("timestamp", "")),
        "footer": {
            "text": "SOC AI Agent • Threat Intelligence Platform",
        },
    }

    payload = {"embeds": [embed]}

    try:
        response = requests.post(
            webhook_url.strip(),
            json=payload,
            timeout=5,
        )
        # Discord zwraca 204 No Content przy sukcesie
        if response.status_code in (200, 204):
            return True, f"Alert wysłany pomyślnie (HTTP {response.status_code})"
        else:
            return False, f"Discord odrzucił wiadomość: HTTP {response.status_code} — {response.text[:200]}"
    except requests.exceptions.Timeout:
        return False, "Przekroczono limit czasu połączenia (timeout 5s)"
    except requests.exceptions.ConnectionError as e:
        return False, f"Błąd połączenia z Discord: {e}"
    except requests.exceptions.RequestException as e:
        return False, f"Nieoczekiwany błąd requests: {e}"


# ── Funkcja 2: Wysyłanie alertów wsadowych ────────────────────────────────────

def send_batch_alerts(webhook_url: str, df_malicious: pd.DataFrame, max_alerts: int = 5) -> tuple[int, int]:
    """
    Wysyła serię alertów dla złośliwych zdarzeń z DataFrame.

    Parametry:
        webhook_url  (str):           URL Discord Webhooka.
        df_malicious (pd.DataFrame):  DataFrame zawierający TYLKO złośliwe rekordy.
                                      Oczekiwane kolumny: source_ip, event_type,
                                      threat_type, severity, reasoning, timestamp.
        max_alerts   (int):           Maksymalna liczba alertów do wysłania (domyślnie 5).

    Zwraca:
        tuple[int, int]: (liczba wysłanych, liczba błędów)
    """
    if not _validate_webhook_url(webhook_url):
        return 0, 0

    if df_malicious is None or df_malicious.empty:
        return 0, 0

    # Ogranicz do max_alerts wierszy
    df_limited = df_malicious.head(max_alerts)

    sent_count  = 0
    error_count = 0

    for _, row in df_limited.iterrows():
        event_data = {
            "source_ip":   row.get("source_ip",   "N/A"),
            "event_type":  row.get("event_type",  "N/A"),
            "threat_type": row.get("threat_type", "N/A"),
            "severity":    row.get("severity",    "info"),
            "reasoning":   row.get("reasoning",   "Brak analizy"),
            "timestamp":   str(row.get("timestamp", "")),
        }

        success, _ = send_discord_alert(webhook_url, event_data)

        if success:
            sent_count += 1
        else:
            error_count += 1

        # Pauza między wysyłkami — ochrona przed rate limitem Discord
        time.sleep(0.5)

    return sent_count, error_count


# ── Funkcja 3: Zbiorczy Embed z podsumowaniem ─────────────────────────────────

def send_summary_embed(webhook_url: str, stats_dict: dict) -> tuple[bool, str]:
    """
    Wysyła jeden zbiorczy Embed z podsumowaniem stanu bezpieczeństwa.

    Parametry:
        webhook_url (str): URL Discord Webhooka.
        stats_dict  (dict): Słownik ze statystykami. Oczekiwane klucze:
            - total_events (int)
            - malicious    (int)
            - top_threat   (str)
            - top_ip       (str)

    Zwraca:
        tuple[bool, str]: (sukces, komunikat opisowy)
    """
    if not _validate_webhook_url(webhook_url):
        return False, "Nieprawidłowy URL Webhooka. Musi zaczynać się od https://discord.com/api/webhooks/"

    total_events = int(stats_dict.get("total_events", 0))
    malicious    = int(stats_dict.get("malicious",    0))
    top_threat   = str(stats_dict.get("top_threat",  "N/A"))
    top_ip       = str(stats_dict.get("top_ip",      "N/A"))

    # Kolor zależny od obecności złośliwych zdarzeń
    color = 0xFF0000 if malicious > 0 else 0x00FF00
    status_emoji = "🔴" if malicious > 0 else "🟢"
    status_text  = "ZAGROŻENIA WYKRYTE" if malicious > 0 else "BRAK ZAGROŻEŃ"

    embed = {
        "title": f"{status_emoji} SOC PODSUMOWANIE — {status_text}",
        "color": color,
        "fields": [
            {
                "name": "📊 Wszystkie zdarzenia",
                "value": str(total_events),
                "inline": True,
            },
            {
                "name": "☣️ Złośliwe zdarzenia",
                "value": str(malicious),
                "inline": True,
            },
            {
                "name": "📈 Wskaźnik zagrożeń",
                "value": f"{(malicious / total_events * 100):.1f}%" if total_events > 0 else "0%",
                "inline": True,
            },
            {
                "name": "🏆 Dominujący typ zagrożenia",
                "value": top_threat,
                "inline": True,
            },
            {
                "name": "🌐 Najaktywniejszy IP",
                "value": top_ip,
                "inline": True,
            },
        ],
        "footer": {
            "text": "SOC AI Agent • Threat Intelligence Platform",
        },
    }

    payload = {"embeds": [embed]}

    try:
        response = requests.post(
            webhook_url.strip(),
            json=payload,
            timeout=5,
        )
        if response.status_code in (200, 204):
            return True, "Podsumowanie wysłane pomyślnie"
        else:
            return False, f"Discord odrzucił wiadomość: HTTP {response.status_code} — {response.text[:200]}"
    except requests.exceptions.Timeout:
        return False, "Przekroczono limit czasu połączenia (timeout 5s)"
    except requests.exceptions.ConnectionError as e:
        return False, f"Błąd połączenia z Discord: {e}"
    except requests.exceptions.RequestException as e:
        return False, f"Nieoczekiwany błąd requests: {e}"


# ── Funkcja 4: Panel ustawień Streamlit ───────────────────────────────────────

def render_discord_settings_panel() -> str | None:
    """
    Renderuje panel ustawień Discord Webhooków w interfejsie Streamlit.
    Wywołaj tę funkcję wewnątrz bloku `with tab1:` w dashboard.py,
    po wyświetleniu metryk.

    Zwraca:
        str | None: Aktualny Webhook URL lub None jeśli nie podano / nieprawidłowy.

    Przykład użycia w dashboard.py:
    ─────────────────────────────────
    # from modules.discord_notifier import render_discord_settings_panel, send_batch_alerts
    # with tab1:
    #     ... (metryki, wykresy)
    #     render_discord_settings_panel()
    """

    # Inicjalizacja session_state
    if "discord_webhook" not in st.session_state:
        st.session_state["discord_webhook"] = os.getenv("DISCORD_WEBHOOK_URL", "")
    if "discord_auto_alerts" not in st.session_state:
        st.session_state["discord_auto_alerts"] = False

    with st.expander("🔔 Alerty Discord"):

        # ── Pole Webhook URL ──────────────────────────────────────────────────
        webhook_url = st.text_input(
            "Discord Webhook URL",
            value=st.session_state["discord_webhook"],
            placeholder="https://discord.com/api/webhooks/...",
            help="Skopiuj URL Webhooka z ustawień kanału Discord (Integracje → Webhooks).",
            key="discord_webhook_input",
        )
        # Zapisz aktualną wartość w session_state
        st.session_state["discord_webhook"] = webhook_url

        # Walidacja na żywo
        if webhook_url and not _validate_webhook_url(webhook_url):
            st.warning("⚠️ URL musi zaczynać się od `https://discord.com/api/webhooks/`")
            webhook_url = None

        # ── Toggle automatycznych alertów ─────────────────────────────────────
        auto_alerts = st.checkbox(
            "Włącz automatyczne alerty",
            value=st.session_state["discord_auto_alerts"],
            help="Automatycznie wysyłaj alerty gdy pojawią się nowe złośliwe zdarzenia.",
            key="discord_auto_alerts_toggle",
        )
        st.session_state["discord_auto_alerts"] = auto_alerts

        st.divider()

        # ── Sekcja testowa ────────────────────────────────────────────────────
        st.markdown("#### 🧪 Test połączenia")

        if st.button("🧪 Wyślij test", disabled=(not webhook_url)):
            # Testowy event z przykładowymi danymi
            test_event = {
                "source_ip":   "192.168.1.100",
                "event_type":  "TEST_CONNECTION",
                "threat_type": "Test Alert",
                "severity":    "medium",
                "reasoning":   "To jest testowa wiadomość z SOC AI Agent. Jeśli ją widzisz — integracja działa poprawnie.",
                "timestamp":   pd.Timestamp.now().isoformat(),
            }
            with st.spinner("Wysyłanie testu..."):
                success, message = send_discord_alert(webhook_url, test_event)
            if success:
                st.success(f"✅ {message}")
            else:
                st.error(f"❌ {message}")

        st.divider()

        # ── Przycisk podsumowania ─────────────────────────────────────────────
        st.markdown("#### 📤 Podsumowanie zbiorcze")

        if st.button("📤 Wyślij podsumowanie teraz", disabled=(not webhook_url)):
            # Pobierz dane z session_state (zasilane przez dashboard.py)
            df = st.session_state.get("df", None)

            if df is not None and not df.empty:
                total_events = len(df)
                malicious    = int(df["is_malicious"].sum()) if "is_malicious" in df.columns else 0

                # Najczęstszy typ zagrożenia
                if "threat_type" in df.columns and malicious > 0:
                    top_threat = (
                        df[df["is_malicious"] == True]["threat_type"]
                        .value_counts()
                        .idxmax()
                        if not df[df["is_malicious"] == True].empty
                        else "N/A"
                    )
                else:
                    top_threat = "N/A"

                # Najaktywniejszy IP
                top_ip = (
                    df["source_ip"].value_counts().idxmax()
                    if "source_ip" in df.columns and not df.empty
                    else "N/A"
                )

                stats = {
                    "total_events": total_events,
                    "malicious":    malicious,
                    "top_threat":   str(top_threat),
                    "top_ip":       str(top_ip),
                }
            else:
                # Brak danych w session_state — wyślij puste podsumowanie
                stats = {
                    "total_events": 0,
                    "malicious":    0,
                    "top_threat":   "Brak danych",
                    "top_ip":       "Brak danych",
                }

            with st.spinner("Wysyłanie podsumowania..."):
                success, message = send_summary_embed(webhook_url, stats)
            if success:
                st.success(f"✅ {message}")
            else:
                st.error(f"❌ {message}")

        st.divider()

        # ── Alerty krytycznych zdarzeń ────────────────────────────────────────
        st.markdown("#### 📡 Automatyczne alerty krytycznych zdarzeń")

        col_left, col_right = st.columns([2, 1])

        with col_left:
            max_alerts = st.number_input(
                "Maks. liczba alertów",
                min_value=1,
                max_value=20,
                value=5,
                step=1,
                help="Ogranicz liczbę wysyłanych alertów, aby uniknąć spamu.",
                key="discord_max_alerts",
            )

        with col_right:
            st.markdown("<br>", unsafe_allow_html=True)  # wyrównanie pionowe
            send_critical = st.button(
                "Wyślij alerty dla KRYTYCZNYCH zdarzeń",
                disabled=(not webhook_url),
                key="discord_send_critical",
            )

        if send_critical:
            df = st.session_state.get("df", None)

            if df is None or df.empty:
                st.warning("⚠️ Brak danych do wysłania. Załaduj dane w zakładce głównej.")
            else:
                # Filtruj tylko złośliwe zdarzenia o wysokim priorytecie
                if "is_malicious" in df.columns and "severity" in df.columns:
                    df_critical = df[
                        (df["is_malicious"] == True) &
                        (df["severity"].str.lower().isin(["critical", "high"]))
                    ].copy()
                elif "is_malicious" in df.columns:
                    df_critical = df[df["is_malicious"] == True].copy()
                else:
                    df_critical = pd.DataFrame()

                if df_critical.empty:
                    st.info("ℹ️ Brak krytycznych / wysokich zdarzeń do wysłania.")
                else:
                    with st.spinner(f"Wysyłanie do {min(int(max_alerts), len(df_critical))} alertów..."):
                        sent, errors = send_batch_alerts(webhook_url, df_critical, max_alerts=int(max_alerts))
                    if errors == 0:
                        st.success(f"✅ Wysłano {sent} alertów bez błędów.")
                    else:
                        st.warning(f"⚠️ Wysłano {sent} alertów, {errors} nie udało się wysłać.")

    # Zwróć aktualny (zwalidowany) webhook URL
    return st.session_state.get("discord_webhook") or None
