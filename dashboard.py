import streamlit as st
import pandas as pd
import os
from dotenv import load_dotenv

load_dotenv()

try:
    from scapy.all import rdpcap, IP, TCP, UDP
    import networkx as nx
    from pyvis.network import Network
    PCAP_LIBS_AVAILABLE = True
except ImportError:
    PCAP_LIBS_AVAILABLE = False

try:
    import plotly.express as px
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

import streamlit.components.v1 as components

# Importy z modułów
from modules.database import load_data, clear_logs
from modules.threat_intel import check_ip_reputation, ask_ai_about_ip, check_virustotal, ask_ai_about_file
from modules.malware_analyzer import calculate_hashes_and_entropy, extract_interesting_strings
from modules.pdf_generator import create_pdf_report
from modules.soar_engine import render_soar_tab
from modules.discord_notifier import render_discord_settings_panel, send_batch_alerts
from modules.mitre_engine import render_mitre_tab
from modules.geoip_mapper import render_geoip_tab

# Ustawienia strony
st.set_page_config(
    page_title="SOC AI Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── GRANATOWA SZATA GRAFICZNA SOC (CUSTOM CSS) ───────────────────────────────
st.markdown(
    """
    <style>
    /* Główne tło aplikacji – głęboki granat SOC */
    .stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"] {
        background: linear-gradient(160deg, #09111e 0%, #0d1b2a 55%, #112238 100%) !important;
        color: #f1f5f9 !important;
    }

    [data-testid="stHeader"] {
        background: rgba(9, 17, 30, 0.85) !important;
        backdrop-filter: blur(8px);
        border-bottom: 1px solid rgba(56, 189, 248, 0.12);
    }

    /* Panel boczny (Sidebar) */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #070e1a 0%, #0c1829 100%) !important;
        border-right: 1px solid rgba(56, 189, 248, 0.18) !important;
    }

    /* Karty metryk KPI */
    div[data-testid="stMetric"] {
        background: linear-gradient(145deg, rgba(22, 36, 59, 0.92) 0%, rgba(15, 26, 44, 0.95) 100%) !important;
        border: 1px solid rgba(56, 189, 248, 0.22) !important;
        border-left: 4px solid #38bdf8 !important;
        border-radius: 12px !important;
        padding: 16px 20px !important;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35) !important;
        transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
    }
    div[data-testid="stMetric"]:hover {
        transform: translateY(-2px);
        border-color: rgba(56, 189, 248, 0.55) !important;
        box-shadow: 0 12px 28px rgba(56, 189, 248, 0.12) !important;
    }
    div[data-testid="stMetricLabel"] > div {
        color: #94a3b8 !important;
        font-size: 0.85rem !important;
        font-weight: 600 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.04em !important;
    }
    div[data-testid="stMetricValue"] > div {
        color: #f8fafc !important;
        font-weight: 700 !important;
    }

    /* Pasek zakładek (Tabs) */
    div[data-baseweb="tab-list"] {
        background-color: rgba(15, 25, 42, 0.85) !important;
        padding: 6px 8px !important;
        border-radius: 12px !important;
        border: 1px solid rgba(56, 189, 248, 0.18) !important;
        gap: 6px !important;
    }
    button[data-baseweb="tab"] {
        background-color: transparent !important;
        border-radius: 8px !important;
        color: #94a3b8 !important;
        font-weight: 600 !important;
        padding: 10px 18px !important;
        transition: all 0.2s ease !important;
    }
    button[data-baseweb="tab"]:hover {
        background-color: rgba(56, 189, 248, 0.1) !important;
        color: #e2e8f0 !important;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        background: linear-gradient(135deg, rgba(2, 132, 199, 0.35) 0%, rgba(30, 64, 175, 0.45) 100%) !important;
        color: #38bdf8 !important;
        border: 1px solid rgba(56, 189, 248, 0.45) !important;
        box-shadow: 0 4px 12px rgba(2, 132, 199, 0.2) !important;
    }

    /* Przyciski */
    .stButton > button, .stDownloadButton > button {
        border-radius: 8px !important;
        font-weight: 600 !important;
        border: 1px solid rgba(56, 189, 248, 0.3) !important;
        background: linear-gradient(135deg, #162844 0%, #101f36 100%) !important;
        color: #f1f5f9 !important;
        transition: all 0.2s ease !important;
    }
    .stButton > button:hover, .stDownloadButton > button:hover {
        border-color: #38bdf8 !important;
        background: linear-gradient(135deg, #1e3a5f 0%, #162b49 100%) !important;
        box-shadow: 0 0 14px rgba(56, 189, 248, 0.25) !important;
        color: #ffffff !important;
    }

    /* Pola tekstowe, selectboxy, file uploader i expandery */
    [data-testid="stExpander"] {
        background-color: rgba(18, 30, 50, 0.75) !important;
        border: 1px solid rgba(56, 189, 248, 0.2) !important;
        border-radius: 10px !important;
    }
    [data-testid="stFileUploader"] {
        background-color: rgba(18, 30, 50, 0.65) !important;
        border: 1px dashed rgba(56, 189, 248, 0.35) !important;
        border-radius: 12px !important;
        padding: 12px !important;
    }
    [data-testid="stDataFrame"] {
        border: 1px solid rgba(56, 189, 248, 0.2) !important;
        border-radius: 10px !important;
        overflow: hidden !important;
    }

    /* Baner tytułowy SOC */
    .soc-hero-banner {
        background: linear-gradient(135deg, rgba(16, 33, 58, 0.95) 0%, rgba(11, 23, 42, 0.95) 100%);
        border: 1px solid rgba(56, 189, 248, 0.28);
        border-left: 5px solid #38bdf8;
        border-radius: 14px;
        padding: 20px 26px;
        margin-bottom: 20px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
    }
    .soc-hero-title {
        font-size: 1.75rem;
        font-weight: 800;
        color: #f8fafc;
        margin: 0;
        letter-spacing: -0.01em;
    }
    .soc-hero-subtitle {
        font-size: 0.95rem;
        color: #94a3b8;
        margin-top: 5px;
        margin-bottom: 0;
    }
    .soc-status-badge {
        background: rgba(16, 185, 129, 0.15);
        border: 1px solid rgba(16, 185, 129, 0.45);
        color: #34d399;
        padding: 6px 14px;
        border-radius: 999px;
        font-size: 0.78rem;
        font-weight: 700;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        white-space: nowrap;
    }
    .soc-section-card {
        background: rgba(19, 32, 54, 0.7);
        border: 1px solid rgba(56, 189, 248, 0.18);
        border-radius: 10px;
        padding: 14px 18px;
        margin-bottom: 14px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ─── WCZYTANIE DANYCH DO PAMIĘCI SESJI ────────────────────────────────────────
try:
    df_global = load_data()
    st.session_state["df"] = df_global
    db_online = True
except Exception as db_err:
    df_global = pd.DataFrame()
    st.session_state["df"] = df_global
    db_online = False

# ─── PANEL BOCZNY (SIDEBAR) ───────────────────────────────────────────────────
with st.sidebar:
    st.markdown(
        """
        <div style="text-align: center; padding: 10px 0 16px 0; border-bottom: 1px solid rgba(56,189,248,0.2); margin-bottom: 16px;">
            <div style="font-size: 2.4rem;">🛡️</div>
            <div style="font-size: 1.15rem; font-weight: 800; color: #f8fafc; letter-spacing: 0.03em;">SOC COMMAND CENTER</div>
            <div style="font-size: 0.78rem; color: #38bdf8; font-weight: 600;">SIEM • DFIR • SOAR • AI</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("##### 📡 Status Komponentów")
    groq_ok = bool(os.getenv("GROQ_API_KEY", "").strip())
    abuse_ok = bool(os.getenv("ABUSEIPDB_API_KEY", "").strip())
    vt_ok = bool(os.getenv("VT_API_KEY", "").strip())

    st.markdown(
        f"""
        <div class="soc-section-card" style="font-size: 0.85rem; line-height: 1.85;">
            <div>🗄️ <b>Baza PostgreSQL:</b> <span style="float:right; color:{'#34d399' if db_online else '#f87171'};">{'● Online' if db_online else '○ Offline'}</span></div>
            <div>🤖 <b>Silnik AI (Groq):</b> <span style="float:right; color:{'#34d399' if groq_ok else '#fbbf24'};">{'● Aktywny' if groq_ok else '○ Brak klucza'}</span></div>
            <div>🌐 <b>AbuseIPDB OSINT:</b> <span style="float:right; color:{'#34d399' if abuse_ok else '#fbbf24'};">{'● Aktywny' if abuse_ok else '○ Brak klucza'}</span></div>
            <div>🧬 <b>VirusTotal API:</b> <span style="float:right; color:{'#34d399' if vt_ok else '#fbbf24'};">{'● Aktywny' if vt_ok else '○ Brak klucza'}</span></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("##### 📊 Szybka Telemetria")
    total_ev = len(df_global)
    mal_ev = int((df_global["is_malicious"] == True).sum()) if not df_global.empty and "is_malicious" in df_global.columns else 0
    pcap_ti_count = len(st.session_state.get("ti_results", []))
    st.markdown(
        f"""
        <div class="soc-section-card" style="font-size: 0.85rem; line-height: 1.85;">
            <div>Zdarzenia Sysmon: <b style="float:right; color:#38bdf8;">{total_ev}</b></div>
            <div>Wykryte ataki: <b style="float:right; color:#f87171;">{mal_ev}</b></div>
            <div>Hosty z PCAP: <b style="float:right; color:#a78bfa;">{pcap_ti_count}</b></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("##### ⚙️ Zarządzanie Danymi")
    if st.button("🔄 Odśwież wszystkie dane", use_container_width=True, key="sb_refresh"):
        st.cache_data.clear()
        st.rerun()

    if st.button("🗑️ Wyczyść bazę logów", use_container_width=True, key="sb_clear"):
        st.session_state["confirm_clear"] = True

    if st.session_state.get("confirm_clear"):
        st.warning("⚠️ Czy na pewno usunąć wszystkie logi z bazy?")
        sb_c1, sb_c2 = st.columns(2)
        if sb_c1.button("✅ Usuń", type="primary", use_container_width=True, key="sb_confirm_yes"):
            try:
                deleted = clear_logs()
                st.session_state.pop("confirm_clear", None)
                st.session_state.pop("df", None)
                st.cache_data.clear()
                st.toast(f"🗑️ Usunięto {deleted} rekordów z bazy.", icon="✅")
                st.rerun()
            except Exception as e:
                st.error(f"Błąd: {e}")
        if sb_c2.button("❌ Anuluj", use_container_width=True, key="sb_confirm_no"):
            st.session_state.pop("confirm_clear", None)
            st.rerun()

# ─── BANER GŁÓWNY (HERO HEADER) ──────────────────────────────────────────────
st.markdown(
    """
    <div class="soc-hero-banner">
        <div>
            <h1 class="soc-hero-title">🛡️ SOC AI Threat Intelligence Platform</h1>
            <p class="soc-hero-subtitle">
                Zintegrowane centrum operacji bezpieczeństwa: monitoring behawioralny Sysmon, kryminalistyka sieciowa PCAP, analiza DFIR oraz automatyczna odpowiedź SOAR.
            </p>
        </div>
        <div class="soc-status-badge">● SOC TELEMETRY ACTIVE</div>
    </div>
    """,
    unsafe_allow_html=True,
)

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "🔴 Live SOC (Sysmon)", 
    "📦 Analiza PCAP & OSINT", 
    "🧬 Analiza Plików (Malware Triage)",
    "⚡ SOAR & Response",
    "🧠 MITRE ATT&CK & Hunting",
    "🌍 Mapa Ataków (GeoIP)"
])

# ─── ZAKŁADKA 1: GŁÓWNY DASHBOARD ────────────────────────────────────────────
with tab1:
    try:
        df = df_global
        # Automatyczne alerty Discord (gdy włączone)
        if st.session_state.get("discord_auto_alerts") and st.session_state.get("discord_webhook"):
            df_mal = df[df["is_malicious"] == True] if "is_malicious" in df.columns else pd.DataFrame()
            if not df_mal.empty:
                sent, errs = send_batch_alerts(
                    st.session_state["discord_webhook"], df_mal,
                    max_alerts=st.session_state.get("discord_max_alerts", 5))
                if sent > 0:
                    st.toast(f"📡 Wysłano {sent} automatycznych alertów Discord", icon="🔔")

        if not df.empty:
            malicious_count = int((df["is_malicious"] == True).sum()) if "is_malicious" in df.columns else 0
            malicious_pct = (malicious_count / len(df) * 100) if len(df) > 0 else 0.0
            crit_high_count = (
                int(df["severity"].astype(str).str.lower().isin(["critical", "high"]).sum())
                if "severity" in df.columns else 0
            )
            last_ip = str(df["source_ip"].iloc[0]) if "source_ip" in df.columns else "N/A"
            last_rep = check_ip_reputation(last_ip)

            # 4 karty KPI
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("📊 Wszystkie zdarzenia", len(df), "Live Telemetry")
            col2.metric(
                "🚨 Wykryte ataki",
                malicious_count,
                f"{malicious_pct:.1f}% wszystkich zdarzeń",
                delta_color="inverse" if malicious_count > 0 else "off",
            )
            col3.metric(
                "🔥 Krytyczne / Wysokie",
                crit_high_count,
                "Priorytet reakcji IR",
                delta_color="inverse" if crit_high_count > 0 else "off",
            )
            col4.metric("🌐 Reputacja ostatniego IP", last_rep, f"IP: {last_ip}")

            st.markdown("<br>", unsafe_allow_html=True)

            # Wykresy analityczne na żywo (jeśli dostępny Plotly)
            if PLOTLY_AVAILABLE and "severity" in df.columns and "threat_type" in df.columns:
                with st.expander("📈 Wizualna Analityka Zagrożeń (Rozkład Ważności i Wektorów Ataków)", expanded=True):
                    ch_col1, ch_col2 = st.columns(2)
                    with ch_col1:
                        sev_counts = (
                            df["severity"]
                            .astype(str)
                            .str.lower()
                            .value_counts()
                            .reset_index()
                        )
                        sev_counts.columns = ["Poziom", "Liczba"]
                        color_map = {
                            "critical": "#ef4444",
                            "high": "#f97316",
                            "medium": "#eab308",
                            "low": "#38bdf8",
                            "info": "#10b981",
                        }
                        fig_sev = px.bar(
                            sev_counts,
                            x="Poziom",
                            y="Liczba",
                            color="Poziom",
                            color_discrete_map=color_map,
                            title="Rozkład zdarzeń wg poziomu ważności (Severity)",
                        )
                        fig_sev.update_layout(
                            paper_bgcolor="rgba(0,0,0,0)",
                            plot_bgcolor="rgba(13,27,42,0.6)",
                            font_color="#f1f5f9",
                            height=280,
                            margin=dict(l=10, r=10, t=40, b=10),
                            showlegend=False,
                        )
                        st.plotly_chart(fig_sev, use_container_width=True)

                    with ch_col2:
                        df_mal_only = df[df["is_malicious"] == True] if "is_malicious" in df.columns else df
                        target_df = df_mal_only if not df_mal_only.empty else df
                        threat_counts = (
                            target_df["threat_type"]
                            .astype(str)
                            .value_counts()
                            .head(7)
                            .reset_index()
                        )
                        threat_counts.columns = ["Kategoria Zagrożenia", "Liczba"]
                        fig_thr = px.bar(
                            threat_counts,
                            x="Liczba",
                            y="Kategoria Zagrożenia",
                            orientation="h",
                            color="Liczba",
                            color_continuous_scale="Blues",
                            title="Dominujące kategorie zagrożeń (Top 7)",
                        )
                        fig_thr.update_layout(
                            paper_bgcolor="rgba(0,0,0,0)",
                            plot_bgcolor="rgba(13,27,42,0.6)",
                            font_color="#f1f5f9",
                            height=280,
                            yaxis=dict(autorange="reversed"),
                            coloraxis_showscale=False,
                            margin=dict(l=10, r=10, t=40, b=10),
                        )
                        st.plotly_chart(fig_thr, use_container_width=True)

            # Pasek filtrowania i wyszukiwania dziennika zdarzeń
            st.subheader("📋 Dziennik Zdarzeń Bezpieczeństwa (Live)")
            f_col1, f_col2, f_col3, f_col4 = st.columns([2, 1.2, 1, 0.8])
            with f_col1:
                search_query = st.text_input(
                    "🔍 Szukaj w logach (IP, typ zdarzenia, uzasadnienie AI):",
                    placeholder="np. 185.220, Brute Force, lsass.exe...",
                    key="live_search",
                )
            with f_col2:
                sev_options = ["Wszystkie", "critical", "high", "medium", "low"]
                selected_sev = st.selectbox("⚡ Poziom zagrożenia:", sev_options, key="live_sev_filter")
            with f_col3:
                st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
                only_malicious = st.toggle("🚨 Tylko wykryte ataki", value=False, key="live_mal_toggle")
            with f_col4:
                st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
                if st.button("🔄 Odśwież", use_container_width=True, key="tab1_refresh"):
                    st.cache_data.clear()
                    st.rerun()

            expected_cols = ['timestamp', 'source_ip', 'event_type', 'is_malicious', 'threat_type', 'severity', 'reasoning']
            available_cols = [c for c in expected_cols if c in df.columns]
            filtered_df = df[available_cols].copy()

            if only_malicious and "is_malicious" in filtered_df.columns:
                filtered_df = filtered_df[filtered_df["is_malicious"] == True]

            if selected_sev != "Wszystkie" and "severity" in filtered_df.columns:
                filtered_df = filtered_df[filtered_df["severity"].astype(str).str.lower() == selected_sev]

            if search_query.strip():
                q = search_query.strip().lower()
                mask = filtered_df.astype(str).apply(lambda x: x.str.lower().str.contains(q, na=False)).any(axis=1)
                filtered_df = filtered_df[mask]

            def highlight_malicious(row):
                return ['background-color: rgba(239, 68, 68, 0.22); color: #fecaca;'] * len(row) if row.get('is_malicious', False) else [''] * len(row)

            st.caption(f"Wyświetlono **{len(filtered_df)}** z **{len(df)}** zarejestrowanych zdarzeń.")
            st.dataframe(
                filtered_df.style.apply(highlight_malicious, axis=1),
                use_container_width=True,
                hide_index=True,
                height=420,
            )

            st.markdown("---")
            bot_col1, bot_col2 = st.columns([1.4, 1])
            with bot_col1:
                render_discord_settings_panel()
            with bot_col2:
                st.markdown("#### 📄 Raportowanie Dowodowe (Chain of Custody)")
                st.write("Wygeneruj oficjalny raport PDF zawierający zestawienie najnowszych incydentów oraz wnioski analityczne AI.")
                pdf_filename1 = "raport_soc_live.pdf"
                if st.button("📑 Generuj Raport PDF (Zdarzenia Sysmon)", use_container_width=True):
                    create_pdf_report(
                        "Raport Dowodowy SOC - Zdarzenia Sysmon",
                        {"Ostatnie Zdarzenia (Max 100)": filtered_df.head(100)},
                        pdf_filename1,
                    )
                    with open(pdf_filename1, "rb") as pdf_file:
                        st.download_button(
                            label="📥 Pobierz gotowy raport Sysmon (.pdf)",
                            data=pdf_file,
                            file_name="Raport_Sysmon_SOC.pdf",
                            mime="application/pdf",
                            use_container_width=True,
                        )
        else:
            st.info(
                "ℹ️ Brak logów w bazie danych. Uruchom `python generate_test_logs.py` aby wstrzyknąć scenariusze testowe "
                "lub włącz `python windows_agent.py` w celu zbierania zdarzeń na żywo."
            )
    except Exception as e:
        st.error(f"Błąd przetwarzania danych: {e}")

# ─── ZAKŁADKA 2: ANALIZATOR PCAP ─────────────────────────────────────────────
with tab2:
    st.header("📦 Analiza Zrzutów Sieciowych (Deep Packet Inspection)")
    st.write("Wgraj plik z ruchem sieciowym (`.pcap`), aby zrekonstruować topologię połączeń, zweryfikować reputację adresów IP w AbuseIPDB i uzyskać komentarz śledczy AI.")

    uploaded_file = st.file_uploader("Wybierz plik zrzutu sieciowego (.pcap)", type="pcap", key="pcap_uploader")

    if uploaded_file is not None:
        if not PCAP_LIBS_AVAILABLE:
            st.error("Brak zainstalowanych bibliotek do analizy PCAP (`scapy`, `networkx`, `pyvis`). Zainstaluj je poleceniem:\n```bash\npip install scapy networkx pyvis\n```")
        else:
            with st.spinner("Analizowanie pakietów i weryfikowanie zagrożeń przez AI..."):
                temp_path = "temp_upload.pcap"
                try:
                    with open(temp_path, "wb") as f:
                        f.write(uploaded_file.getbuffer())

                    packets = rdpcap(temp_path)
                    pcap_data = []
                    unique_ips = set()

                    for pkt in packets[:1000]:
                        if IP in pkt:
                            src_ip = pkt[IP].src
                            dst_ip = pkt[IP].dst
                            protocol = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "Inny")
                            unique_ips.add(src_ip)
                            unique_ips.add(dst_ip)
                            pcap_data.append({"Zrodlo": src_ip, "Cel": dst_ip, "Protokol": protocol})

                    ip_status = {}
                    ti_results = []

                    for ip in unique_ips:
                        reputation = check_ip_reputation(ip)
                        is_malicious = "⚠️ Zagrożenie" in reputation
                        ip_status[ip] = is_malicious

                        ai_comment = "Brak uwag (Zaufany IP)"
                        if is_malicious:
                            ai_comment = ask_ai_about_ip(ip, reputation)

                        ti_results.append({
                            "Adres IP": ip,
                            "Reputacja": reputation,
                            "Komentarz Sledczy AI": ai_comment,
                        })

                    # Zapisujemy do session_state, aby SOAR i GeoIP miały dostęp do danych
                    st.session_state["ti_results"] = ti_results

                    mal_nodes_count = sum(1 for v in ip_status.values() if v)
                    p_col1, p_col2, p_col3, p_col4 = st.columns(4)
                    p_col1.metric("📦 Przeanalizowane pakiety", len(pcap_data))
                    p_col2.metric("🌐 Unikalne hosty IP", len(unique_ips))
                    p_col3.metric(
                        "🚨 Złośliwe węzły IP",
                        mal_nodes_count,
                        "Wykryte w AbuseIPDB",
                        delta_color="inverse" if mal_nodes_count > 0 else "off",
                    )
                    p_col4.metric("📄 Plik źródłowy", uploaded_file.name)

                    st.subheader("🕸️ Interaktywny Graf Topologii Połączeń")
                    G = nx.Graph()

                    for ip in unique_ips:
                        node_color = "#ef4444" if ip_status[ip] else "#38bdf8"
                        G.add_node(ip, color=node_color, title=f"IP: {ip}")

                    for row in pcap_data:
                        src = row["Zrodlo"]
                        dst = row["Cel"]
                        edge_color = "#ef4444" if (ip_status[src] or ip_status[dst]) else "#475569"
                        G.add_edge(src, dst, title=row["Protokol"], color=edge_color)

                    net = Network(height="520px", width="100%", bgcolor="#0d1b2a", font_color="#f8fafc")
                    net.from_nx(G)
                    net.repulsion(node_distance=160, spring_length=160)

                    path_html = "network_graph.html"
                    net.write_html(path_html)
                    with open(path_html, 'r', encoding='utf-8') as HtmlFile:
                        components.html(HtmlFile.read(), height=540)

                    st.subheader("🌐 Raport Threat Intelligence & Komentarz AI")
                    df_ti = pd.DataFrame(ti_results)
                    st.dataframe(df_ti, use_container_width=True, hide_index=True)

                    with st.expander("📋 Szczegółowy wykaz wyodrębnionych pakietów", expanded=False):
                        df_pcap = pd.DataFrame(pcap_data)
                        st.dataframe(df_pcap, use_container_width=True, height=300)
                    if "df_pcap" not in locals():
                        df_pcap = pd.DataFrame(pcap_data)

                    st.markdown("---")
                    st.subheader("📄 Generowanie Raportu Śledczego (PDF)")
                    pdf_filename2 = "raport_soc_pcap.pdf"

                    if st.button("📑 Generuj Raport PDF (Analiza PCAP)"):
                        create_pdf_report(
                            "Raport Dowodowy SOC - Analiza Sieciowa (PCAP)",
                            {
                                "Analiza IP (Threat Intelligence)": df_ti,
                                "Wyodrebnione Pakiety (Max 250)": df_pcap.head(250),
                            },
                            pdf_filename2,
                        )
                        with open(pdf_filename2, "rb") as pdf_file:
                            st.download_button(
                                label="📥 Pobierz wygenerowany raport PCAP (.pdf)",
                                data=pdf_file,
                                file_name="Raport_PCAP_SOC.pdf",
                                mime="application/pdf",
                            )

                except Exception as e:
                    st.error(f"Błąd analizy pliku PCAP: {e}")
                finally:
                    if os.path.exists(temp_path):
                        try:
                            os.remove(temp_path)
                        except Exception:
                            pass

# ─── ZAKŁADKA 3: ANALIZA PLIKÓW (MALWARE TRIAGE) ─────────────────────────────
with tab3:
    st.header("🧬 Kryminalistyczna Analiza Plików (Static Malware Triage)")
    st.write("Wgraj podejrzany plik wykonywalny, skrypt lub dokument, aby wyliczyć sumy kontrolne, zbadać entropię Shannona, wyodrębnić ciągi znaków i zweryfikować reputację w VirusTotal.")

    uploaded_malware = st.file_uploader("Wybierz plik do bezpiecznej analizy statycznej", type=None, key="malware_uploader")

    if uploaded_malware is not None:
        with st.spinner("Przeprowadzanie analizy statycznej i korelacji z VirusTotal..."):
            file_bytes = uploaded_malware.getvalue()
            filename = uploaded_malware.name
            file_size_kb = round(len(file_bytes) / 1024, 2)

            md5, sha1, sha256, entropy = calculate_hashes_and_entropy(file_bytes)
            suspicious_strings, total_strings = extract_interesting_strings(file_bytes)
            vt_result = check_virustotal(sha256)
            ai_file_opinion = ask_ai_about_file(filename, entropy, vt_result, suspicious_strings)

            m_col1, m_col2, m_col3, m_col4 = st.columns(4)
            m_col1.metric("📁 Rozmiar pliku", f"{file_size_kb} KB", filename)

            entropy_status = "⚠️ Wysoka (Pakowany/Szyfrowany)" if entropy > 7.0 else "Normalna"
            m_col2.metric(
                "📐 Entropia Shannona (0-8)",
                f"{entropy}",
                entropy_status,
                delta_color="inverse" if entropy > 7.0 else "normal",
            )
            m_col3.metric("🛡️ Status VirusTotal", vt_result.split("(")[0])
            m_col4.metric("🔍 Podejrzane ciągi", len(suspicious_strings), f"z {total_strings} ciągów ASCII")

            st.subheader("🔑 Kryptograficzne Sumy Kontrolne (Chain of Custody)")
            df_hashes = pd.DataFrame([
                {"Algorytm": "MD5", "Suma kontrolna (Hash)": md5},
                {"Algorytm": "SHA-1", "Suma kontrolna (Hash)": sha1},
                {"Algorytm": "SHA-256", "Suma kontrolna (Hash)": sha256},
                {"Algorytm": "VirusTotal Werdykt", "Suma kontrolna (Hash)": vt_result},
            ])
            st.dataframe(df_hashes, use_container_width=True, hide_index=True)

            st.subheader("🤖 Ekspertyza Śledcza AI (DFIR Analyst)")
            if "⚠️" in vt_result or entropy > 7.0:
                st.error(ai_file_opinion)
            else:
                st.info(ai_file_opinion)

            st.subheader(f"🔍 Wyodrębnione podejrzane artefakty ({len(suspicious_strings)} z {total_strings} ciągów)")
            if suspicious_strings:
                df_strings = pd.DataFrame({"Podejrzany ciąg znaków (ASCII)": suspicious_strings})
                st.dataframe(df_strings, use_container_width=True, height=260)
            else:
                df_strings = pd.DataFrame({"Podejrzany ciąg znaków (ASCII)": ["Brak oczywistych artefaktów w kodzie niespakowanym"]})
                st.success("Nie wykryto typowych podejrzanych ciągów (IP, URL, PowerShell, API iniekcji).")

            st.markdown("---")
            st.subheader("📄 Generowanie Raportu Analizy Pliku (PDF)")
            pdf_filename3 = "raport_soc_malware.pdf"

            df_summary_pdf = pd.DataFrame([{
                "Plik": filename,
                "Rozmiar_KB": file_size_kb,
                "Entropia": entropy,
                "VirusTotal": vt_result,
                "Opinia_AI": ai_file_opinion,
            }])

            if st.button("📑 Generuj Raport PDF (Analiza Pliku)"):
                create_pdf_report(
                    f"Raport DFIR - Analiza Pliku ({filename})",
                    {
                        "Podsumowanie Sledcze i AI": df_summary_pdf,
                        "Sumy Kontrolne (Hashes)": df_hashes,
                        "Wyodrebnione Artefakty (Strings)": df_strings,
                    },
                    pdf_filename3,
                )
                with open(pdf_filename3, "rb") as pdf_file:
                    st.download_button(
                        label="📥 Pobierz wygenerowany raport DFIR (.pdf)",
                        data=pdf_file,
                        file_name=f"Raport_DFIR_{filename}.pdf",
                        mime="application/pdf",
                    )

# ─── ZAKŁADKA 4: SOAR & ACTIVE RESPONSE ──────────────────────────────────────
with tab4:
    soar_ips = []
    try:
        if "ti_results" in st.session_state:
            soar_ips = [
                r["Adres IP"] for r in st.session_state["ti_results"]
                if "⚠️ Zagrożenie" in r.get("Reputacja", "")
            ]
        if not soar_ips and not df_global.empty and "is_malicious" in df_global.columns and "source_ip" in df_global.columns:
            soar_ips = list(df_global[df_global["is_malicious"] == True]["source_ip"].dropna().unique())
    except Exception:
        soar_ips = []
    render_soar_tab(malicious_ips_from_context=soar_ips)

# ─── ZAKŁADKA 5: MITRE ATT&CK & THREAT HUNTING ───────────────────────────────
with tab5:
    try:
        from modules.database import engine as db_engine
        df_mitre = st.session_state.get("df")
        if df_mitre is None:
            df_mitre = load_data()
    except Exception:
        df_mitre = pd.DataFrame()
        db_engine = None
    render_mitre_tab(df_mitre, engine=db_engine)

# ─── ZAKŁADKA 6: MAPA GEOGRAFICZNA ATAKÓW ────────────────────────────────────
with tab6:
    _df_geo = st.session_state.get("df", pd.DataFrame())

    _pcap_ips = []
    _pcap_mal = []
    if "ti_results" in st.session_state:
        for r in st.session_state["ti_results"]:
            _pcap_ips.append(r["Adres IP"])
            _pcap_mal.append("⚠️ Zagrożenie" in r.get("Reputacja", ""))

    render_geoip_tab(
        df_logs=_df_geo,
        extra_ips=_pcap_ips if _pcap_ips else None,
        extra_malicious=_pcap_mal if _pcap_mal else None,
    )
