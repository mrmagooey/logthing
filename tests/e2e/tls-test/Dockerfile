FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir requests urllib3

# Copy test script and certificates
COPY tls-test/entrypoint.py ./entrypoint.py
COPY certs/ca.crt /app/certs/ca.crt
COPY certs/client.crt /app/certs/client.crt
COPY certs/client.key /app/certs/client.key

ENTRYPOINT ["python", "entrypoint.py"]
