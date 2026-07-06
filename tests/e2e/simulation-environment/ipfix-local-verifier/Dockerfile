FROM python:3.12-slim

RUN pip install --no-cache-dir pyarrow

COPY ipfix-local-verifier/entrypoint.py /entrypoint.py

ENTRYPOINT ["python3", "/entrypoint.py"]
