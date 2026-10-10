FROM python:3.12-alpine
RUN apk add --no-cache docker-cli tzdata
WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ /app/
COPY automation/ /app/automation/
COPY gunicorn.conf.py /app/
ENV PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN mkdir -p /app/data /app/geo /app/config /app/logs /app/automation-state
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD python -c "import base64,os,urllib.request; r=urllib.request.Request('http://127.0.0.1:9191/geo/status'); r.add_header('Authorization','Basic '+base64.b64encode((os.environ.get('FCP_ADMIN_USER','admin')+':'+os.environ['FCP_ADMIN_PASSWORD']).encode()).decode()); urllib.request.urlopen(r,timeout=3).read()"
CMD ["gunicorn", "--config", "/app/gunicorn.conf.py", "ui:app"]
