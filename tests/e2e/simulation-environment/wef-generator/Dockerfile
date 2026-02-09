FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir requests pyyaml

COPY fixtures ./fixtures
COPY wef-generator/entrypoint.py ./entrypoint.py

ENTRYPOINT ["python", "entrypoint.py"]
