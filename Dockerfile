FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Créer le dossier .streamlit et lier les secrets
RUN mkdir -p .streamlit

# Copier le secrets.toml depuis /etc/secrets vers .streamlit au démarrage
CMD cp /etc/secrets/secrets.toml .streamlit/secrets.toml 2>/dev/null || true && \
    streamlit run app.py --server.port=8501 --server.address=0.0.0.0
