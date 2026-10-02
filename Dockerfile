FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8080 \
    DATA_DIR=/data

WORKDIR /app

# Stdlib-only service: no pip install step, so an image build never
# depends on a package index.  Sources are copied, then a build manifest
# with a digest of exactly the shipped files is generated, so the
# acceptance suite can prove the running image matches its sources.
COPY app/ ./app/
COPY verify/ ./verify/
COPY docker/gen_build_info.py /tmp/gen_build_info.py
RUN python3 /tmp/gen_build_info.py /app > /build-info.json \
    && rm /tmp/gen_build_info.py

RUN mkdir -p /data && useradd -r -u 10001 seabed && chown -R seabed:seabed /data /app
USER seabed

EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=3s --start-period=2s --retries=12 \
    CMD python3 -c "import json,os,urllib.request; r=urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8080')+'/healthz',timeout=2); json.load(r)"

CMD ["python3", "-m", "app"]
