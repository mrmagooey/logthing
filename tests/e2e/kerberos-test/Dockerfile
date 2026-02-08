FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir requests

COPY kerberos-test/entrypoint.py ./entrypoint.py

ENTRYPOINT ["python", "entrypoint.py"]
