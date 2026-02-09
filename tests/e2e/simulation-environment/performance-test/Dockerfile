FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir requests boto3

COPY performance-test/entrypoint.py ./entrypoint.py

ENTRYPOINT ["python", "entrypoint.py"]
