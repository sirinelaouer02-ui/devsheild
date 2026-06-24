FROM python:3.11-slim

# Répertoire de travail dans le conteneur
WORKDIR /app

# Copie et installe les dépendances d'abord (couche cachée)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie le reste du code
COPY . .

# Port exposé
EXPOSE 5000

# Utilisateur non-root pour la sécurité
RUN adduser --disabled-password --gecos '' appuser
USER appuser

# Commande de démarrage
CMD ["python", "run.py"]