# Używamy oficjalnego, lekkiego obrazu Pythona
FROM python:3.11-slim

# Ustawiamy katalog roboczy wewnątrz kontenera
WORKDIR /app

# Kopiujemy plik z wymaganiami i instalujemy zależności
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Kopiujemy kod naszej aplikacji
COPY ./app ./app
COPY . .

# Wystawiamy port, na którym działa FastAPI
EXPOSE 8000

# Komenda startowa uruchamiająca serwer uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]