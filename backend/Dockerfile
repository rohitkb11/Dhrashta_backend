FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py ./
COPY static ./static
RUN mkdir /data && useradd --uid 10001 --no-create-home app && chown app:app /data
USER app
EXPOSE 8000
# A single process owns the WebSocket subscribers and durable replay journal.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
