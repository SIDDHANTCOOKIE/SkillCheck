# SkillCheck is a single FastAPI service that also serves the static
# frontend (see FRONTEND_DIR in api/main.py, which resolves to ../frontend
# relative to this backend) — one container, one process, unlike a split
# frontend/backend deploy. Build with the *repo root* as context so both
# backend/ and frontend/ land in the image at the paths main.py expects:
#   docker build -f backend/Dockerfile -t skillcheck .
FROM python:3.11-slim

# git is a runtime dependency, not a build tool here — ingest.py shells out
# to `git clone` for the /api/scan/repo endpoint. python:3.11-slim doesn't
# ship it.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/ backend/
COPY frontend/ frontend/

WORKDIR /app/backend
EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
