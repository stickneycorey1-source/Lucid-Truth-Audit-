diff --git a/Dockerfile b/Dockerfile
index 389f0bc14aadc7cd337f1e93360bac4a733968fa..da4bc0a348c0ca245774d17b286fc83337354dc2 100648
--- a/Dockerfile
+++ b/Dockerfile
@@ -1,29 +1,49 @@
+# syntax=docker/dockerfile:1.6
+FROM python:3.12-slim AS builder
+
+ENV PYTHONDONTWRITEBYTECODE=1 \
+    PYTHONUNBUFFERED=1 \
+    PIP_NO_CACHE_DIR=1 \
+    PIP_DISABLE_PIP_VERSION_CHECK=1
+
+WORKDIR /build
+
+# Install build dependencies only if wheels are needed
+RUN apt-get update && apt-get install -y --no-install-recommends \
+    gcc \
+    && rm -rf /var/lib/apt/lists/*
+
+COPY requirements.txt .
+RUN pip wheel --wheel-dir=/build/wheels -r requirements.txt
+
+
+FROM python:3.12-slim AS runtime
+
+ENV PYTHONDONTWRITEBYTECODE=1 \
+    PYTHONUNBUFFERED=1 \
+    PYTHONPATH=/app \
+    HOST=0.0.0.0 \
+    PORT=10000
+
+WORKDIR /app
+
+# Create non-root user for runtime security
+RUN groupadd --system appgroup && useradd --system --gid appgroup --no-create-home appuser
+
+# Copy prebuilt wheels and install without cache
+COPY --from=builder /build/wheels /wheels
+COPY requirements.txt .
+RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt \
+    && rm -rf /wheels requirements.txt
+
+# Copy application code
+COPY --chown=appuser:appgroup . .
+
+USER appuser
+
+EXPOSE 10000
+
+HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
+    CMD python -c "import os, urllib.request; port = os.getenv('PORT', '10000'); urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=4).read()" || exit 1
+
+CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-10000} --workers 1 --proxy-headers --forwarded-allow-ips='*'"]