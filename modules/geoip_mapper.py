"""
modules/geoip_mapper.py
────────────────────────
Moduł GeoIP – Wizualna Mapa Geograficzna Ataków
Zamienia publiczne adresy IP z logów i plików PCAP na współrzędne
geograficzne i renderuje interaktywną mapę świata w Plotly.

Źródło danych: ip-api.com (bezpłatne, bez klucza, limit 45 req/min)
Dokumentacja: http://ip-api.com/docs/api:json
"""

import time
import requests
import streamlit as st
import pandas as pd

try:
    import plotly.express as px
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False


# ─── Stałe ────────────────────────────────────────────────────────────────────

# Ip-api.com: 45 req/min dla HTTP, batch do 100 IP na jedno żądanie
_BATCH_URL  = "http://ip-api.com/batch"
_SINGLE_URL = "http://ip-api.com/json/{ip}"
_FIELDS     = "status,country,countryCode,regionName,city,lat,lon,isp,org,as,query"

# Prywatne zakresy – pomijamy (nie mają sensu na mapie)
_PRIVATE_PREFIXES = (
    "127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "169.254.", "::1", "fc", "fd",
)

# Kolory markerów: złośliwe IP = czerwone, czyste = niebieskie
_COLOR_MALICIOUS = "#FF4B4B"
_COLOR_CLEAN     = "#1f77b4"
_COLOR_UNKNOWN   = "#FFA500"

# ─── Helpery ──────────────────────────────────────────────────────────────────

def _is_public_ip(ip: str) -> bool:
    """Zwraca True jeśli IP jest publicznym adresem (nie prywatnym/loopback)."""
    return bool(ip) and not ip.startswith(_PRIVATE_PREFIXES)


def _geolocate_batch(ip_list: list[str]) -> list[dict]:
    """
    Geolokalizuje listę publicznych IP za pomocą ip-api.com (batch API).
    Przetwarza max 100 IP na żądanie, respektuje rate-limit.

    Args:
        ip_list: Lista publicznych adresów IP.

    Returns:
        Lista słowników z danymi geolokalizacji.
    """
    results = []
    # Podziel na paczki po 100 (limit API)
    chunks = [ip_list[i:i + 100] for i in range(0, len(ip_list), 100)]

    for chunk_idx, chunk in enumerate(chunks):
        if chunk_idx > 0:
            time.sleep(1.5)  # Respektuj rate-limit (45 req/min)

        payload = [{"query": ip, "fields": _FIELDS} for ip in chunk]
        try:
            resp = requests.post(_BATCH_URL, json=payload, timeout=10)
            if resp.status_code == 200:
                results.extend(resp.json())
            else:
                # Fallback: dodaj puste rekordy
                for ip in chunk:
                    results.append({"status": "fail", "query": ip})
        except Exception:
            for ip in chunk:
                results.append({"status": "fail", "query": ip})

    return results


# ─── Główna funkcja geolokalizacji ───────────────────────────────────────────

@st.cache_data(ttl=1800, show_spinner=False)
def geolocate_ips(ip_list: tuple[str, ...]) -> pd.DataFrame:
    """
    Geolokalizuje listę unikalnych publicznych IP i zwraca DataFrame.
    Wynik jest cachowany przez 30 minut (ttl=1800).

    Args:
        ip_list: Krotka unikalnych publicznych adresów IP (krotka dla cache).

    Returns:
        DataFrame z kolumnami:
            ip, country, countryCode, city, regionName,
            lat, lon, isp, org, asn, status
    """
    public_ips = [ip for ip in ip_list if _is_public_ip(ip)]
    if not public_ips:
        return pd.DataFrame()

    raw = _geolocate_batch(public_ips)

    rows = []
    for entry in raw:
        if entry.get("status") == "success":
            rows.append({
                "ip":          entry.get("query", ""),
                "country":     entry.get("country", "Nieznany"),
                "countryCode": entry.get("countryCode", ""),
                "city":        entry.get("city", ""),
                "regionName":  entry.get("regionName", ""),
                "lat":         float(entry.get("lat", 0)),
                "lon":         float(entry.get("lon", 0)),
                "isp":         entry.get("isp", ""),
                "org":         entry.get("org", ""),
                "asn":         entry.get("as", ""),
            })
        else:
            rows.append({
                "ip":          entry.get("query", ""),
                "country":     "Nieznany",
                "countryCode": "",
                "city":        "",
                "regionName":  "",
                "lat":         None,
                "lon":         None,
                "isp":         "",
                "org":         "",
                "asn":         "",
            })

    df = pd.DataFrame(rows)
    return df


# ─── Budowanie danych mapy ────────────────────────────────────────────────────

def build_map_dataframe(
    df_logs: pd.DataFrame,
    ip_col: str = "source_ip",
    malicious_col: str | None = "is_malicious",
    extra_ips: list[str] | None = None,
    extra_malicious: list[bool] | None = None,
) -> pd.DataFrame:
    """
    Łączy logi SOC lub listę IP z danymi geolokalizacji.

    Args:
        df_logs:         DataFrame z logami (może być pusty).
        ip_col:          Nazwa kolumny z adresami IP w df_logs.
        malicious_col:   Nazwa kolumny bool (złośliwy/czysty). None = wszystkie nieznane.
        extra_ips:       Dodatkowe IP (np. z PCAP) spoza df_logs.
        extra_malicious: Czy extra_ips są złośliwe (lista bool, dopasowana do extra_ips).

    Returns:
        DataFrame gotowy do wyświetlenia na mapie, z kolumnami:
        ip, country, city, lat, lon, isp, asn, is_malicious, color, label
    """
    ip_malicious_map: dict[str, bool | None] = {}

    # Zbierz IP z logów
    if not df_logs.empty and ip_col in df_logs.columns:
        for _, row in df_logs.iterrows():
            ip = str(row[ip_col])
            mal = bool(row[malicious_col]) if malicious_col and malicious_col in df_logs.columns else None
            # Jeśli ten sam IP widziany jako złośliwy choć raz → oznacz jako złośliwy
            if ip not in ip_malicious_map or mal:
                ip_malicious_map[ip] = mal

    # Zbierz extra IP (np. z PCAP)
    if extra_ips:
        for i, ip in enumerate(extra_ips):
            mal = extra_malicious[i] if extra_malicious and i < len(extra_malicious) else None
            if ip not in ip_malicious_map or mal:
                ip_malicious_map[ip] = mal

    if not ip_malicious_map:
        return pd.DataFrame()

    # Geolokalizuj wszystkie unikalne publiczne IP
    all_public = tuple(ip for ip in ip_malicious_map if _is_public_ip(ip))
    if not all_public:
        return pd.DataFrame()

    df_geo = geolocate_ips(all_public)
    if df_geo.empty:
        return pd.DataFrame()

    # Dopasuj informacje o złośliwości
    df_geo["is_malicious"] = df_geo["ip"].map(ip_malicious_map)

    # Przypisz kolory i etykiety
    def get_color(val):
        if val is True:
            return _COLOR_MALICIOUS
        if val is False:
            return _COLOR_CLEAN
        return _COLOR_UNKNOWN

    df_geo["color"] = df_geo["is_malicious"].apply(get_color)

    def get_label(row):
        status = "🔴 ZŁOŚLIWY" if row["is_malicious"] is True else \
                 "🟢 Czysty"   if row["is_malicious"] is False else \
                 "🟠 Nieznany"
        parts = [f"<b>{row['ip']}</b>", status]
        if row["city"]:
            parts.append(f"📍 {row['city']}, {row['country']}")
        else:
            parts.append(f"🌍 {row['country']}")
        if row["isp"]:
            parts.append(f"🏢 ISP: {row['isp']}")
        if row["asn"]:
            parts.append(f"🔗 {row['asn']}")
        return "<br>".join(parts)

    df_geo["label"] = df_geo.apply(get_label, axis=1)

    # Usuń rekordy bez współrzędnych
    df_geo = df_geo.dropna(subset=["lat", "lon"])
    df_geo = df_geo[df_geo["lat"] != 0]

    return df_geo


# ─── Renderowanie mapy Plotly ─────────────────────────────────────────────────

def render_attack_map(df_map: pd.DataFrame, title: str = "Mapa Geograficzna Ataków") -> None:
    """
    Renderuje interaktywną mapę świata w Plotly ze znacznikami IP.

    Args:
        df_map: DataFrame z kolumnami ip, lat, lon, color, label, country, is_malicious.
        title:  Tytuł wyświetlany nad mapą.
    """
    if df_map.empty:
        st.info("🌍 Brak publicznych adresów IP do wyświetlenia na mapie.")
        return

    n_malicious = int((df_map["is_malicious"] == True).sum())
    n_clean     = int((df_map["is_malicious"] == False).sum())
    n_unknown   = int(df_map["is_malicious"].isna().sum())
    n_countries = df_map["country"].nunique()

    # Metryki nad mapą
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("🌍 Unikalnych IP",    len(df_map))
    m2.metric("🔴 Złośliwych IP",    n_malicious)
    m3.metric("🟢 Czystych IP",      n_clean)
    m4.metric("🗺️ Krajów źródłowych", n_countries)

    # Buduj figurę Plotly
    fig = go.Figure()

    # Warstwa 1: Czyste / nieznane IP (w tle)
    df_other = df_map[df_map["is_malicious"] != True]
    if not df_other.empty:
        fig.add_trace(go.Scattergeo(
            lat=df_other["lat"],
            lon=df_other["lon"],
            mode="markers",
            marker=dict(
                size=8,
                color=df_other["color"],
                opacity=0.65,
                line=dict(width=0.5, color="white"),
            ),
            text=df_other["label"],
            hoverinfo="text",
            name="🟢 Czyste / Nieznane",
        ))

    # Warstwa 2: Złośliwe IP (na wierzchu, większe)
    df_mal = df_map[df_map["is_malicious"] == True]
    if not df_mal.empty:
        fig.add_trace(go.Scattergeo(
            lat=df_mal["lat"],
            lon=df_mal["lon"],
            mode="markers",
            marker=dict(
                size=12,
                color=_COLOR_MALICIOUS,
                opacity=0.9,
                symbol="x",
                line=dict(width=1.5, color="#FF0000"),
            ),
            text=df_mal["label"],
            hoverinfo="text",
            name="🔴 Złośliwe IP",
        ))

    fig.update_layout(
        title=dict(text=title, font=dict(size=16, color="#f8fafc"), x=0.5),
        geo=dict(
            showland=True,     landcolor="#162844",
            showocean=True,    oceancolor="#0a1424",
            showlakes=True,    lakecolor="#0a1424",
            showcountries=True, countrycolor="#294875",
            showcoastlines=True, coastlinecolor="#294875",
            showframe=False,
            projection_type="natural earth",
            bgcolor="#0d1b2a",
        ),
        paper_bgcolor="#0d1b2a",
        plot_bgcolor="#0d1b2a",
        font_color="#f8fafc",
        legend=dict(
            bgcolor="rgba(13,27,42,0.85)",
            bordercolor="rgba(56,189,248,0.3)",
            borderwidth=1,
        ),
        margin=dict(l=0, r=0, t=40, b=0),
        height=520,
    )

    st.plotly_chart(fig, use_container_width=True)

    # Tabela z detalami pod mapą
    with st.expander("📋 Szczegółowa tabela geolokalizacji IP"):
        cols_show = ["ip", "is_malicious", "country", "city", "regionName", "isp", "asn"]
        cols_show = [c for c in cols_show if c in df_map.columns]
        df_display = df_map[cols_show].copy()
        df_display["is_malicious"] = df_display["is_malicious"].map(
            {True: "🔴 Złośliwy", False: "🟢 Czysty", None: "🟠 Nieznany"}
        )
        df_display.columns = ["IP", "Status", "Kraj", "Miasto", "Region", "ISP", "ASN"][: len(cols_show)]
        st.dataframe(df_display, use_container_width=True, hide_index=True)


# ─── Wykres słupkowy: Top krajów ──────────────────────────────────────────────

def render_country_barchart(df_map: pd.DataFrame) -> None:
    """Renderuje wykres słupkowy Top 10 krajów źródłowych ataków."""
    if df_map.empty:
        return

    df_mal = df_map[df_map["is_malicious"] == True]
    if df_mal.empty:
        st.info("Brak złośliwych IP z przypisaną geolokalizacją.")
        return

    top_countries = (
        df_mal.groupby(["country", "countryCode"])
        .size()
        .reset_index(name="Liczba złośliwych IP")
        .sort_values("Liczba złośliwych IP", ascending=False)
        .head(10)
    )

    fig = px.bar(
        top_countries,
        x="Liczba złośliwych IP",
        y="country",
        orientation="h",
        color="Liczba złośliwych IP",
        color_continuous_scale="Reds",
        labels={"country": "Kraj"},
        title="🔴 Top 10 krajów źródłowych złośliwych IP",
    )
    fig.update_layout(
        paper_bgcolor="#0d1b2a",
        plot_bgcolor="#0d1b2a",
        font_color="#f8fafc",
        height=350,
        yaxis=dict(autorange="reversed"),
        coloraxis_showscale=False,
        margin=dict(l=0, r=0, t=40, b=0),
    )
    st.plotly_chart(fig, use_container_width=True)


# ─── Pełna zakładka Streamlit ────────────────────────────────────────────────

def render_geoip_tab(
    df_logs: pd.DataFrame,
    extra_ips: list[str] | None = None,
    extra_malicious: list[bool] | None = None,
) -> None:
    """
    Renderuje pełną zakładkę GeoIP w dashboardzie Streamlit.

    Wywołaj w dashboard.py:
        with tab6:
            render_geoip_tab(df, extra_ips=pcap_ips, extra_malicious=pcap_mal)

    Args:
        df_logs:         DataFrame z logami Sysmon (kolumny: source_ip, is_malicious).
        extra_ips:       Dodatkowe IP (np. z PCAP) jako lista stringów.
        extra_malicious: Czy extra_ips są złośliwe.
    """
    st.header("🌍 Mapa Geograficzna Ataków (GeoIP)")
    st.write(
        "Interaktywna mapa świata pokazująca geograficzne źródła zagrożeń. "
        "Dane geolokalizacji pobierane są z **ip-api.com** (bezpłatnie, bez klucza API)."
    )

    if not PLOTLY_AVAILABLE:
        st.error("Brak zainstalowanej biblioteki `plotly`. Zainstaluj ją poleceniem:\n```bash\npip install plotly\n```")
        return

    # Legenda
    col_l1, col_l2, col_l3, col_l4 = st.columns(4)
    col_l1.markdown("🔴 **Złośliwe IP** — wykryte ataki")
    col_l2.markdown("🟢 **Czyste IP** — ruch normalny")
    col_l3.markdown("🟠 **Nieznane** — IP z PCAP bez oceny")
    col_l4.markdown("✖ **Kształt X** = złośliwy marker")

    st.markdown("---")

    # Przycisk odświeżania (czyści cache GeoIP)
    col_r1, col_r2, _ = st.columns([1, 1, 4])
    if col_r1.button("🔄 Odśwież mapę", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    # Filtr: pokaż tylko złośliwe lub wszystkie
    show_only_malicious = col_r2.toggle("Tylko złośliwe IP", value=False)

    # Buduj dane mapy
    with st.spinner("🌐 Geolokalizowanie adresów IP... (ip-api.com)"):
        df_map = build_map_dataframe(
            df_logs=df_logs,
            extra_ips=extra_ips,
            extra_malicious=extra_malicious,
        )

    if df_map.empty:
        st.warning(
            "Brak publicznych adresów IP do wyświetlenia. "
            "Upewnij się, że logi zawierają publiczne IP (nie prywatne 192.168.x.x / 10.x.x.x)."
        )
        return

    if show_only_malicious:
        df_map_filtered = df_map[df_map["is_malicious"] == True]
        if df_map_filtered.empty:
            st.info("Brak złośliwych IP z przypisaną lokalizacją.")
        else:
            render_attack_map(df_map_filtered, "🔴 Mapa Złośliwych IP")
    else:
        render_attack_map(df_map, "🌍 Mapa Geograficzna Ataków")

    st.markdown("---")

    # Wykres słupkowy krajów
    col_bar, col_isp = st.columns([1, 1])
    with col_bar:
        render_country_barchart(df_map)

    with col_isp:
        # Top ISP/Organizacji dla złośliwych IP
        df_mal = df_map[df_map["is_malicious"] == True]
        if not df_mal.empty and "isp" in df_mal.columns:
            st.subheader("🏢 Top ISP złośliwych IP")
            top_isp = (
                df_mal[df_mal["isp"] != ""]
                .groupby("isp")
                .size()
                .reset_index(name="Liczba IP")
                .sort_values("Liczba IP", ascending=False)
                .head(8)
            )
            if not top_isp.empty:
                fig_isp = px.bar(
                    top_isp, x="Liczba IP", y="isp", orientation="h",
                    color="Liczba IP", color_continuous_scale="Oranges",
                    labels={"isp": "ISP / Organizacja"},
                )
                fig_isp.update_layout(
                    paper_bgcolor="#0d1b2a", plot_bgcolor="#0d1b2a",
                    font_color="#f8fafc", height=350,
                    yaxis=dict(autorange="reversed"),
                    coloraxis_showscale=False,
                    margin=dict(l=0, r=0, t=10, b=0),
                )
                st.plotly_chart(fig_isp, use_container_width=True)

