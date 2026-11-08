import os
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

def get_groq_model() -> str:
    return os.getenv("GROQ_MODEL", "qwen/qwen3.8-27b")

@st.cache_data(ttl=3600)
def check_ip_reputation(ip_address):
    if not ip_address or not isinstance(ip_address, str):
        return "Brak danych"
        
    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not abuse_key:
        return "⚠️ Brak klucza ABUSEIPDB_API_KEY w .env"
    if ip_address.startswith(("127.", "192.168.", "10.", "172.")):
        return "Sieć Lokalna / Zaufany"
        
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {'ipAddress': ip_address, 'maxAgeInDays': '365'}
    headers = {'Accept': 'application/json', 'Key': abuse_key}
    
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=5)
        if response.status_code == 200:
            score = response.json()['data']['abuseConfidenceScore']
            if score > 0:
                return f"⚠️ Zagrożenie (Wynik: {score}%)"
            return "✅ Czysty"
        return "Brak danych"
    except (requests.exceptions.RequestException, KeyError, ValueError) as e:
        return f"Błąd API: {e}"

@st.cache_data(ttl=3600)
def ask_ai_about_ip(ip, reputation_score):
    try:
        groq_key_raw = os.getenv("GROQ_API_KEY") 
        if not groq_key_raw:
            return "Błąd: Brak klucza Groq w pliku .env"
            
        groq_key = groq_key_raw.strip()

        prompt = f"Jesteś analitykiem bezpieczeństwa. Adres IP {ip} ma wynik '{reputation_score}' w AbuseIPDB. Napisz jedno bardzo krótkie, fachowe zdanie wyjaśniające z czym możemy mieć do czynienia w ruchu sieciowym (np. skaner, botnet). Pisz po polsku."
        
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {groq_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": get_groq_model(), 
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3
        }
        
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"].strip()
        else:
            return f"Błąd {response.status_code}: {response.text}"
            
    except Exception as e:
        return f"Błąd połączenia: {e}"

@st.cache_data(ttl=3600)
def check_virustotal(sha256_hash):
    vt_key_raw = os.getenv("VT_API_KEY")
    if not vt_key_raw:
        return "Brak klucza VT_API_KEY w pliku .env (Analiza tylko lokalna)"
    
    vt_key = vt_key_raw.strip()
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": vt_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            if malicious > 0 or suspicious > 0:
                return f"⚠️ Złośliwy (Wykrycia: {malicious}/{total} silników AV)"
            return f"✅ Czysty (0/{total} silników AV)"
        elif response.status_code == 404:
            return "🔍 Nieznany plik (Brak hasha w bazie VirusTotal)"
        else:
            return f"Błąd API VT: Status {response.status_code}"
    except Exception as e:
        return f"Błąd połączenia z VT: {e}"

@st.cache_data(ttl=3600)
def ask_ai_about_file(filename, entropy, vt_result, suspicious_strings):
    try:
        groq_key_raw = os.getenv("GROQ_API_KEY") 
        if not groq_key_raw:
            return "Błąd: Brak klucza Groq w pliku .env"
            
        groq_key = groq_key_raw.strip()
        strings_sample = ", ".join(suspicious_strings[:15]) if suspicious_strings else "Brak podejrzanych ciągów"

        prompt = (
            f"Jesteś inżynierem wstecznej analizy złośliwego oprogramowania (Malware Analyst) w zespole DFIR. "
            f"Przeanalizuj statycznie plik '{filename}'. "
            f"Entropia Shannona: {entropy}/8.0 (powyżej 7.0 sugeruje spakowanie/zaszyfrowanie). "
            f"Wynik VirusTotal: {vt_result}. "
            f"Wyodrębnione podejrzane ciągi znaków (Strings): {strings_sample}. "
            f"Napisz zwięzłą, fachową opinię śledczą (2-3 zdania po polsku), oceniając ryzyko i wskazując na potencjalne zachowanie pliku."
        )
        
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {groq_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": get_groq_model(), 
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3
        }
        
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"].strip()
        else:
            return f"Błąd {response.status_code}: {response.text}"
    except Exception as e:
        return f"Błąd połączenia: {e}"

