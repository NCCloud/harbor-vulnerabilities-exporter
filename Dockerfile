FROM python:3.13-alpine

RUN apk upgrade --no-cache

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY exporter.py /usr/local/bin/

CMD ["/usr/local/bin/exporter.py"]
