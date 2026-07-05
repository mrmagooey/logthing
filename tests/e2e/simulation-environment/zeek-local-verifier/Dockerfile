FROM python:3.12-slim

RUN pip install --no-cache-dir pyarrow

COPY zeek-local-verifier/entrypoint.py /entrypoint.py

ENTRYPOINT ["python3", "/entrypoint.py"]
