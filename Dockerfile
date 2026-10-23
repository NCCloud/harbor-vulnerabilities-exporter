FROM python:3.15-alpine3.24

RUN apk upgrade --no-cache

RUN addgroup -g 1000 exporter && \
    adduser -u 1000 -G exporter -D exporter

ENV PYTHONUNBUFFERED=1

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY exporter.py /usr/local/bin/

RUN chmod +x /usr/local/bin/exporter.py

# numeric user lets kubernetes verify runAsNonRoot
USER 1000:1000

CMD ["/usr/local/bin/exporter.py"]
