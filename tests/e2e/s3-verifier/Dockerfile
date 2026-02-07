FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir boto3 requests

COPY s3-verifier/entrypoint.py ./entrypoint.py

ENTRYPOINT ["python", "entrypoint.py"]
