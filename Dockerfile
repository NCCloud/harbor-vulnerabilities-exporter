FROM python:3.13-alpine

RUN apk upgrade --no-cache

# Create non-root user
RUN addgroup -g 1000 exporter && \
    adduser -u 1000 -G exporter -D exporter

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY exporter.py /usr/local/bin/

USER exporter

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8000/ || exit 1

CMD ["/usr/local/bin/exporter.py"]
