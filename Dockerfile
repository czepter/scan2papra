FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
RUN pip install "requests>=2.32,<3" "img2pdf>=0.6,<0.7" "pillow>=11,<13" \
 && useradd -r -u 1000 app && mkdir -p /data && chown app /data

COPY app.py wsd.py ./
USER app

EXPOSE 8080 6666
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/health')"
CMD ["python", "app.py"]
