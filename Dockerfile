FROM python:3.13-alpine

COPY requirements.txt .

RUN pip install -r requirements.txt

COPY exporter.py /usr/local/bin/

CMD ["/usr/local/bin/exporter.py"]
