FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir flask yara-python

WORKDIR /app

COPY rules.yar /app/rules.yar
COPY sandbox/scanner_api.py /app/scanner_api.py

ENV YARA_RULES_PATH=/app/rules.yar

EXPOSE 8000

CMD ["python", "/app/scanner_api.py"]