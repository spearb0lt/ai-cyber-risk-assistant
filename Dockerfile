FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8000 \
    # fastembed caches the ONNX model here. Setting it explicitly lets the
    # model be baked into the image below, so a cold start does not spend
    # 30 seconds downloading weights before it can answer.
    HF_HOME=/opt/models

WORKDIR /srv

COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# Pull the embedding model at build time rather than first request.
RUN python -c "from fastembed import TextEmbedding; TextEmbedding(model_name='BAAI/bge-small-en-v1.5')" \
    && echo "embedding model cached in $HF_HOME"

COPY app/ ./app/
COPY web/ ./web/
COPY data/ ./data/
COPY scripts/ ./scripts/

EXPOSE 8000

HEALTHCHECK --interval=45s --timeout=10s --start-period=90s --retries=3 \
  CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",8000)}/api/health', timeout=8)"

# sh -c so ${PORT} is expanded by the shell at runtime.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --workers 1 --timeout-keep-alive 65"]
