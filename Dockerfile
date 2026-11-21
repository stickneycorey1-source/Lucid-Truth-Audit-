FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

RUN useradd --create-home --shell /usr/sbin/nologin ltauser
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY lta/ ./lta/
COPY policy_packs/ ./policy_packs/

RUN chown -R ltauser:ltauser /app
USER ltauser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')" || exit 1

CMD ["uvicorn", "lta.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
