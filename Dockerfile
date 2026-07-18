# Single image serving either the Streamlit frontend or the FastAPI service,
# selected at `docker run`/compose time via CMD override. Kept as one image
# in Phase 1-4 per the blueprint; split into apps/web and apps/api images
# only if/when they need independent scaling (see docs/deployment-guide.md).

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps required by lxml/xmltodict-based parsers and psycopg/asyncpg
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libxml2-dev \
        libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8501 8000

# Default: run the Streamlit frontend. Override CMD to run apps/api instead:
#   docker run <image> uvicorn apps.api.main:app --host 0.0.0.0 --port 8000
CMD ["streamlit", "run", "apps/web/Home.py", "--server.address=0.0.0.0"]
