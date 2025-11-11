FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY .streamlit .streamlit
COPY rsa_key.p8 rsa_key.p8

EXPOSE 8501

HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
