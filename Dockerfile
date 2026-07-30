FROM python:3.11-slim

# ✅ Installation des dépendances système pour WeasyPrint
RUN apt-get update && apt-get install -y \
    libglib2.0-0 \
    libgobject-2.0-0 \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libffi-dev \
    libxml2 \
    libxslt1.1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Crée l'utilisateur et le dossier instance avec les bons droits
RUN adduser --disabled-password --gecos '' appuser && \
    mkdir -p /app/instance && \
    chown -R appuser:appuser /app && \
    chmod -R 777 /app/instance

USER appuser

EXPOSE 5000

CMD ["python", "run.py"]