FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir boto3 pyarrow

COPY ipfix-s3-verifier/entrypoint.py ./entrypoint.py

ENTRYPOINT ["python3", "entrypoint.py"]
