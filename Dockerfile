FROM python:3.14-alpine

RUN apk upgrade --no-cache

RUN addgroup -g 1000 exporter && \
    adduser -u 1000 -G exporter -D exporter

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY exporter.py /usr/local/bin/

RUN chmod +x /usr/local/bin/exporter.py

USER exporter

CMD ["/usr/local/bin/exporter.py"]
