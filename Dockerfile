diff --git a/Dockerfile b/Dockerfile
--- a/Dockerfile
+++ b/Dockerfile
@@ -1,57 +1,27 @@
-diff --git a/Dockerfile b/Dockerfile
-index 389f0bc14aadc7cd337f1e93360bac4a733968fa..da4bc0a348c0ca245774d17b286fc83337354dc2 100644
---- a/Dockerfile
-+++ b/Dockerfile
-@@ -1,29 +1,49 @@
-+# syntax=docker/dockerfile:1.6
-+FROM python:3.12-slim AS builder
-+
-+ENV PYTHONDONTWRITEBYTECODE=1 \
-+    PYTHONUNBUFFERED=1 \
-+    PIP_NO_CACHE_DIR=1 \
-+    PIP_DISABLE_PIP_VERSION_CHECK=1
-+
-+WORKDIR /build
-+
-+RUN apt-get update && apt-get install -y --no-install-recommends \
-+    gcc \
-+    && rm -rf /var/lib/apt/lists/*
-+
-+COPY requirements.txt .
-+RUN pip wheel --wheel-dir=/build/wheels -r requirements.txt
-+
-+
-+FROM python:3.12-slim AS runtime
-+
-+ENV PYTHONDONTWRITEBYTECODE=1 \
-+    PYTHONUNBUFFERED=1 \
-+    PYTHONPATH=/app \
-+    HOST=0.0.0.0 \
-+    PORT=10000
-+
-+WORKDIR /app
-+
-+RUN groupadd --system appgroup \
-+    && useradd --system --gid appgroup --no-create-home appuser \
-+    && mkdir -p /var/data \
-+    && chown appuser:appgroup /var/data
-+
-+COPY --from=builder /build/wheels /wheels
-+COPY requirements.txt .
-+RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt \
-+    && rm -rf /wheels requirements.txt
-+
-+COPY --chown=appuser:appgroup . .
-+
-+USER appuser
-+
-+EXPOSE 10000
-+
-+HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
-+    CMD python -c "import os, urllib.request; port=os.getenv('PORT','10000'); urllib.request.urlopen(f'http://127.0.0.1:{port}/health', timeout=4).read()" || exit 1
-+
-+CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-10000} --workers 1 --proxy-headers --forwarded-allow-ips='*'"]
+FROM python:3.11-slim
+
+ENV PYTHONDONTWRITEBYTECODE=1 \
+    PYTHONUNBUFFERED=1
+
+WORKDIR /app
+
+COPY requirements.txt .
+RUN pip install --no-cache-dir -r requirements.txt
+
+COPY app ./app
+COPY lta ./lta
+COPY policy_packs ./policy_packs
+COPY static ./static
+
+RUN adduser --disabled-password --gecos "" appuser \
+    && mkdir -p /var/data \
+    && chown -R appuser:appuser /app /var/data
+
+USER appuser
+
+EXPOSE 10000
+
+HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
+  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:10000/healthz', timeout=3)" || exit 1
+
+CMD ["uvicorn", "lta.app:app", "--host", "0.0.0.0", "--port", "10000"]