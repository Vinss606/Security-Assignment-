# CLO1: Host/Container-Level Hardening (Non-Root Execution & Minimal Attack Surface)
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create dedicated unprivileged system group & user (PoLP at OS Host Level)
RUN groupadd -r carevault && useradd -r -g carevault -s /sbin/nologin carevault

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY carevault ./carevault
COPY templates ./templates
COPY static ./static
COPY manage.py run.py ./

RUN mkdir -p /app/data /app/certs && chown -R carevault:carevault /app

# Drop root privileges permanently before runtime
USER carevault

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import ssl,urllib.request,sys; ctx=ssl.create_default_context(cafile='/app/certs/carevault-root-ca.crt'); r=urllib.request.urlopen('https://localhost:8443/api/health',context=ctx,timeout=3); sys.exit(0 if r.status==200 else 1)"

CMD ["python", "run.py"]
