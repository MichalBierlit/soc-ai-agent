# 🛡️ SOC AI Threat Intelligence & Active Response Platform

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-ED1C24?style=for-the-badge)](https://attack.mitre.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

An enterprise-grade, AI-assisted **Security Operations Center (SOC)** and **Incident Response (IR)** platform. Designed to ingest behavioral endpoint telemetry (Sysmon / Windows Event Logs), perform deep packet inspection (PCAP), execute static malware triage (DFIR), correlate threat intelligence (AbuseIPDB, VirusTotal), and autonomously generate active containment playbooks and firewall rules (SOAR).

Powered by **Groq LLM (Qwen / Llama 3)** for real-time forensic reasoning, Text-to-SQL threat hunting, and dynamic incident response orchestration.

---

## 📑 Spis Treści / Table of Contents
1. [Key Capabilities](#-key-capabilities)
2. [Architecture Overview](#-architecture-overview)
3. [Technology Stack](#-technology-stack)
4. [Platform Modules](#-platform-modules)
   - [1. 🔴 Live SOC Monitoring & AI Triage](#1--live-soc-monitoring--ai-triage)
   - [2. 📦 PCAP Network Forensics & OSINT](#2--pcap-network-forensics--osint)
   - [3. 🧬 Static Malware Triage (DFIR)](#3--static-malware-triage-dfir)
   - [4. ⚡ SOAR & Active Response](#4--soar--active-response)
   - [5. 🧠 MITRE ATT&CK & Text-to-SQL Threat Hunting](#5--mitre-attck--text-to-sql-threat-hunting)
   - [6. 🌍 GeoIP Global Threat Map](#6--geoip-global-threat-map)
   - [7. 🔔 Discord Real-Time Alerting](#7--discord-real-time-alerting)
5. [Installation & Deployment](#-installation--deployment)
   - [Option A: Docker Compose (Recommended)](#option-a-docker-compose-recommended)
   - [Option B: Local Hybrid Environment](#option-b-local-hybrid-environment)
6. [Generating Synthetic Threat Data](#-generating-synthetic-threat-data)
7. [Deploying Windows Endpoint Agent](#-deploying-windows-endpoint-agent)
8. [Configuration (.env)](#-configuration-env)
9. [MITRE ATT&CK Mapping Matrix](#-mitre-attck-mapping-matrix)
10. [License](#-license)

---

## 🌟 Key Capabilities

- **Real-Time Endpoint Ingestion:** Continuous log telemetry collection from Windows Sysmon (`Microsoft-Windows-Sysmon/Operational`) and standard Windows System Event logs.
- **LLM-Powered Forensic Analyst:** Automated zero-shot security analysis of raw log payloads using high-speed Groq inference (`qwen/qwen3.8-27b` / Llama 3).
- **Network Traffic Reconstruction:** PCAP ingestion with protocol decoding (TCP, UDP, IP), bidirectional communication mapping, and interactive node graphs (NetworkX & PyVis).
- **Static Malware Triage (DFIR):** Instant extraction of cryptographic hashes (MD5, SHA-1, SHA-256), Shannon Entropy calculation (packer/crypter detection >7.0), ASCII IOC string filtering, and VirusTotal reputation lookup.
- **SOAR Engine & Active Response:** Autonomous generation of host-based isolation scripts (Windows `netsh advfirewall` and Linux `iptables`) and structured 5-phase Incident Response Playbooks (NIST/SANS aligned).
- **Threat Hunting with Text-to-SQL:** Analysts can query the database using natural language (e.g. *"Show top 5 malicious IPs from the last 24h"*), which the LLM translates into sanitized, read-only SQL queries with AST validation.
- **Global Threat Intelligence & GeoIP:** IP geolocation mapping (ip-api.com) with interactive Plotly Scattergeo visualizations, ISP/ASN profiling, and AbuseIPDB confidence score tracking.
- **Automated Evidentiary Reporting:** Chain-of-custody PDF report generation (`fpdf2` with text-wrapping and Polish character sanitization).
- **Collaborative Alerting:** Rich Discord Embed webhooks with rate limiting and automated batch alerting for critical severity events.

---

## 🏗️ Architecture Overview

```mermaid
flowchart TD
    subgraph Ingestion["1. Telemetry Ingestion"]
        WIN["Windows Host (Sysmon / Event Log)"] -->|HTTP POST| API["FastAPI Collector (:8000)"]
        SYNTH["generate_test_logs.py (21 Scenarios)"] -->|SQL Insert| DB
    end

    subgraph Intelligence["2. AI & Threat Intelligence"]
        API -->|Raw Event| GROQ["Groq AI (Qwen / Llama 3)"]
        GROQ -->|Structured Verdict| API
        API -->|Persist Analyzed Log| DB[(PostgreSQL :5432 / :5433)]
        
        EXT1["AbuseIPDB API"] -.-> DASH
        EXT2["VirusTotal API v3"] -.-> DASH
        EXT3["ip-api.com (Batch GeoIP)"] -.-> DASH
    end

    subgraph Presentation["3. SOC Dashboard & SOAR"]
        DB --> DASH["Streamlit SOC Dashboard (:8501)"]
        DASH --> TAB1["🔴 Live SOC Triage"]
        DASH --> TAB2["📦 PCAP & Network Graph"]
        DASH --> TAB3["🧬 Malware Analysis"]
        DASH --> TAB4["⚡ SOAR & Firewall Rules"]
        DASH --> TAB5["🧠 MITRE & Text-to-SQL"]
        DASH --> TAB6["🌍 GeoIP Threat Map"]
    end

    subgraph Outputs["4. Alerts & Evidence"]
        DASH -->|Webhooks| DISCORD["Discord Channel (Rich Embeds)"]
        DASH -->|Export| PDF["Forensic PDF Reports"]
        DASH -->|Download| FW["Firewall Scripts (.bat / .sh)"]
    end
```

---

## 🛠️ Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Backend API** | FastAPI, Uvicorn, Pydantic v2 |
| **Frontend UI** | Streamlit, Streamlit Components |
| **Database & ORM** | PostgreSQL 15, SQLAlchemy 2.0, Psycopg2 / Psycopg 3 |
| **AI / LLM Framework** | LangChain, LangChain-Groq (`qwen/qwen3.8-27b`, Llama 3) |
| **Network Forensics** | Scapy (Packet Parsing), NetworkX, PyVis (Physics Network Graph) |
| **Visualizations** | Plotly (Scattergeo, Bar charts), Altair |
| **OSINT & Threat Intel** | AbuseIPDB API v2, VirusTotal API v3, ip-api.com Batch Service |
| **Forensic Reporting** | FPDF2, Textwrap, Cryptographic Hashlib (MD5, SHA1, SHA256) |
| **DevOps & Container** | Docker, Docker Compose, Python Virtualenv (`.venv`) |

---

## 🔍 Platform Modules

### 1. 🔴 Live SOC Monitoring & AI Triage
- Displays real-time ingested events from PostgreSQL.
- Color-coded security logs: malicious activities are dynamically highlighted in soft red.
- Real-time AbuseIPDB confidence score evaluation for newly observed IP addresses.
- One-click **Clear Database** with two-step modal confirmation to prevent accidental data loss.
- Automated export to structured **PDF Forensic Reports**.

### 2. 📦 PCAP Network Forensics & OSINT
- Drag-and-drop ingestion of Wireshark `.pcap` capture files.
- Extracts up to 1,000 packets and generates an interactive, physics-based network topology graph.
- Threat intelligence correlation: nodes and communication edges involving malicious IPs glow red.
- Groq AI forensic commentary explaining connection intent and anomalies.

### 3. 🧬 Static Malware Triage (DFIR)
- Ingests suspicious binaries, scripts, or executables without execution (safe triage).
- Computes cryptographic integrity checksums: **MD5**, **SHA-1**, and **SHA-256**.
- Calculates **Shannon Entropy** ($0.0 - 8.0$ scale): files with entropy $>7.0$ are flagged as packed, encrypted, or obfuscated.
- Regex-based ASCII artifact extractor targeting IPs, URLs, base64 fragments, PowerShell commands, and injection APIs (`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`).
- VirusTotal API v3 hash lookup and automated DFIR investigative summary generated by AI.

### 4. ⚡ SOAR & Active Response
- **Firewall Rule Generator:** Converts identified malicious IP addresses into ready-to-run blocking scripts:
  - **Windows Firewall:** `.bat` batch script deploying bidirectional rules via `netsh advfirewall`.
  - **Linux:** `.sh` shell script deploying `iptables -A INPUT/OUTPUT/FORWARD -j DROP` rules.
- **Autonomous AI Incident Response Playbooks:** Select from 10 predefined attack vectors (Ransomware, Data Exfiltration, C2 Beaconing, Lateral Movement, etc.) or provide custom context. The AI generates a 5-phase Incident Response Playbook formatted according to NIST SP 800-61 / SANS standards.

### 5. 🧠 MITRE ATT&CK & Text-to-SQL Threat Hunting
- Automatic heuristic classification of threat types into MITRE ATT&CK tactics (e.g. *Initial Access*, *Credential Access*, *Execution*, *Impact*) and specific technique IDs (e.g. `T1110`, `T1046`, `T1190`, `T1486`).
- Interactive tactical heatmap showing incident density and maximum severity per technique.
- **Threat Hunting (Text-to-SQL):** Security analysts can write freeform natural language queries (e.g. *"Show all critical severity events from the last 12 hours with their reasoning"*). The system converts this via AI into an AST-validated, read-only `SELECT` query with strict rejection of dangerous keywords (`DROP`, `DELETE`, `UPDATE`, `ALTER`).

### 6. 🌍 GeoIP Global Threat Map
- Batch resolves public threat actors using `ip-api.com` without requiring third-party API keys.
- Renders an interactive Plotly 3D/2D scatter geographic map.
- Provides ISP, Organization, ASN, Country, and City intelligence.
- Top 10 attack origin country rankings and top hosting provider metrics.

### 7. 🔔 Discord Real-Time Alerting
- Integrated Discord Webhook notification panel.
- Color-coded Rich Embeds corresponding to threat severity:
  - 🚨 **CRITICAL:** Red (`#FF0000`)
  - 🔴 **HIGH:** Orange (`#FF6600`)
  - 🟡 **MEDIUM:** Amber (`#FFAA00`)
  - 🔵 **LOW / INFO:** Blue (`#0099FF`)
- Automated batch alerts with rate-limiting pauses (0.5s) to comply with Discord API limits.
- Instant SOC summary status report cards.

---

## 🚀 Installation & Deployment

### Option A: Docker Compose (Recommended)

The easiest way to spin up the complete environment (PostgreSQL, FastAPI Backend, and Streamlit Dashboard):

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/soc-ai-agent.git
   cd soc-ai-agent
   ```

2. **Configure environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env and supply your GROQ_API_KEY (and optionally VT_API_KEY, ABUSEIPDB_API_KEY)
   ```

3. **Launch the stack:**
   ```bash
   docker compose up --build -d
   ```

4. **Access the services:**
   - 🛡️ **Streamlit SOC Dashboard:** [http://localhost:8501](http://localhost:8501)
   - ⚡ **FastAPI Ingestion API:** [http://localhost:8000/docs](http://localhost:8000/docs)
   - 🐘 **PostgreSQL Database:** `localhost:5433` (User: `postgres`, DB: `soc_db`)

---

### Option B: Local Hybrid Environment

If you prefer running Streamlit and FastAPI directly in a Python virtual environment while keeping PostgreSQL in Docker:

1. **Start only the PostgreSQL container:**
   ```bash
   docker compose up -d db
   ```

2. **Create and activate a virtual environment:**
   ```bash
   # Windows PowerShell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up `.env` configuration:**
   ```bash
   cp .env.example .env
   ```

5. **Run the FastAPI Ingestion Backend:**
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

6. **Run the Streamlit Dashboard (in a separate terminal):**
   ```bash
   streamlit run dashboard.py
   ```

---

## 🧪 Generating Synthetic Threat Data

To demonstrate the platform's capabilities with realistic security telemetry without waiting for real attacks, use the built-in generator script:

```bash
# Inject 40 diverse attack scenarios across 48h timeline
python generate_test_logs.py

# Inject 100 scenarios and purge old records first
python generate_test_logs.py --clear --count 100
```

### Covered Threat Scenarios:
- **Critical:** LSASS Process Injection (Mimikatz), Ransomware Bulk File Encryption, C2 Periodic Beaconing, Windows ALPC Privilege Escalation (CVE-2023-21768), HTTPS Data Exfiltration.
- **High:** SSH Credential Stuffing, RDP Brute Force, SQL Injection (`UNION SELECT`), Emotet Trojan Dropper, Full SYN Port Scanning.
- **Medium / Low:** Reconnaissance Service Probes, PowerShell Execution Policy Bypass, Tor Relay Traffic, Clean Internal Traffic Baselines.

---

## 🕵️ Deploying Windows Endpoint Agent

To monitor a live Windows machine and stream its events into the SOC platform:

1. Ensure the FastAPI backend is running on `http://127.0.0.1:8000`.
2. Open PowerShell as **Administrator**.
3. Run the Windows agent:
   ```powershell
   python windows_agent.py
   ```
   *The agent queries `Microsoft-Windows-Sysmon/Operational` (or falls back gracefully to `System` event logs if Sysmon is not installed), sanitizes the telemetry, and forwards each event to `/analyze-and-save/`.*

---

## ⚙️ Configuration (.env)

| Variable | Required | Description | Default |
| :--- | :---: | :--- | :--- |
| `GROQ_API_KEY` | **Yes** | API key for Groq AI inference ([console.groq.com](https://console.groq.com)) | — |
| `GROQ_MODEL` | No | Target Groq LLM model | `qwen/qwen3.8-27b` |
| `VT_API_KEY` | No | VirusTotal v3 API key for file hash reputation | — |
| `ABUSEIPDB_API_KEY` | No | AbuseIPDB API key for IP confidence scoring | — |
| `DISCORD_WEBHOOK_URL`| No | Discord Webhook URL for real-time alerting | — |
| `DATABASE_URL` | No | SQLAlchemy database connection string | `postgresql://postgres:admin_password@localhost:5433/soc_db` |

---

## 🗺️ MITRE ATT&CK Mapping Matrix

| Attack Category | MITRE Tactic | Technique ID | MITRE Technique Name |
| :--- | :--- | :---: | :--- |
| **Brute Force** | Credential Access | `T1110` | Brute Force |
| **Port Scan** | Reconnaissance | `T1046` | Network Service Discovery |
| **SQL Injection** | Initial Access | `T1190` | Exploit Public-Facing Application |
| **XSS** | Execution | `T1059.007` | JavaScript Execution |
| **Command Injection** | Execution | `T1059` | Command and Scripting Interpreter |
| **DDoS** | Impact | `T1498` | Network Denial of Service |
| **Malware** | Execution | `T1204` | User Execution |
| **Ransomware** | Impact | `T1486` | Data Encrypted for Impact |
| **Lateral Movement** | Lateral Movement | `T1021` | Remote Services |
| **Privilege Escalation**| Privilege Escalation | `T1068` | Exploitation for Privilege Escalation |
| **Exfiltration** | Exfiltration | `T1041` | Exfiltration Over C2 Channel |
| **Phishing** | Initial Access | `T1566` | Phishing |
| **C2 Beacon** | Command and Control | `T1071` | Application Layer Protocol |

---

## 📂 Repository Structure

```
soc-ai-agent/
├── app/
│   ├── ai_agent.py             # LangChain & Groq structured log classifier
│   ├── database.py             # FastAPI SQLAlchemy database session & engine
│   ├── main.py                 # FastAPI endpoints (health, logs, AI triage)
│   ├── models.py               # SQLAlchemy ORM models (AnalyzedLog)
│   └── schemas.py              # Pydantic validation schemas (DTOs)
├── modules/
│   ├── database.py             # Streamlit DB bridge, schema auto-init & cleanup
│   ├── discord_notifier.py     # Discord Webhook sender & UI configuration panel
│   ├── geoip_mapper.py         # Batch GeoIP (ip-api.com) & Plotly world map
│   ├── malware_analyzer.py     # Shannon entropy, hash calculation, string parsing
│   ├── mitre_engine.py         # MITRE ATT&CK mapping & Text-to-SQL Threat Hunting
│   ├── pdf_generator.py        # FPDF2 chain-of-custody PDF report generator
│   ├── soar_engine.py          # Firewall rule generator & AI Incident Playbooks
│   └── threat_intel.py         # AbuseIPDB, VirusTotal, and AI threat analysis
├── dashboard.py                # Main Streamlit SOC Application (6 tabs)
├── generate_test_logs.py       # High-fidelity synthetic threat telemetry injector
├── windows_agent.py            # Windows Sysmon & Event Log collector daemon
├── docker-compose.yml          # Multi-container orchestration (DB, API, Dashboard)
├── Dockerfile                  # Container build definition for Python runtime
├── requirements.txt            # Project dependencies
├── .env.example                # Template for environment configuration
├── .gitignore                  # Git exclusion rules
└── LICENSE                     # MIT License
```

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.
