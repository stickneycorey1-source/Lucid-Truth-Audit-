FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY lta ./lta
COPY policy_packs ./policy_packs
COPY static ./static

RUN adduser --disabled-password --gecos "" appuser \
    && mkdir -p /var/data \
    && chown -R appuser:appuser /app /var/data

USER appuser

EXPOSE 10000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:10000/healthz', timeout= exit 1

CMD ["uvicorn", "lta.app:app", "--host", "0.0.0.0", "--port", "10000"]