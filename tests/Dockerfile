FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
WORKDIR /app
COPY backend/requirements.txt /app/requirements.txt
COPY tests/requirements.txt /app/test-requirements.txt
RUN pip install --no-cache-dir -r requirements.txt -r test-requirements.txt
COPY backend/app.py /app/app.py
COPY backend/passive.py backend/ingest.py backend/reports.py backend/report_worker.py backend/investigations.py /app/
COPY tests /app/tests
CMD ["pytest", "-q", "/app/tests"]
