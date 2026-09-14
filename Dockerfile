FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8000 \
    # fastembed does not honour HF_HOME. It takes a cache_dir, which
    # app/embeddings/providers.py reads from this variable, so the weights
    # baked in below are the ones the running app loads.
    EMBED_CACHE_DIR=/opt/models

WORKDIR /srv

COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# Pull the embedding model at build time so a cold start does not spend
# 30 seconds downloading weights before it can answer a request.
RUN python -c "\
from fastembed import TextEmbedding; \
m = TextEmbedding(model_name='BAAI/bge-small-en-v1.5', cache_dir='/opt/models'); \
v = list(m.embed(['warm up the onnx session'])); \
print('cached model, embedding dimension', len(v[0]))"

COPY app/ ./app/
COPY web/ ./web/
COPY data/ ./data/
COPY scripts/ ./scripts/

# Fail the build rather than the deploy if the committed index is missing or
# does not match the embedder, since that would silently degrade retrieval
# to lexical only in production.
RUN python -c "\
from app.retrieval import store; \
i = store.load('local'); \
assert i is not None, 'no vector index committed'; \
assert i.dim == 384, f'unexpected index dimension {i.dim}'; \
print('index ok:', len(i.chunks), 'passages at', i.dim, 'dimensions')"

EXPOSE 8000

HEALTHCHECK --interval=45s --timeout=10s --start-period=90s --retries=3 \
  CMD python -c "import urllib.request,os; urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8000')+'/api/health', timeout=8)"

# sh -c so ${PORT} is expanded by the shell at runtime.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --workers 1 --timeout-keep-alive 65"]
