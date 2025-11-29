FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# install build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# create non-root user early so files can be owned by them
RUN groupadd -r app && useradd -r -g app -m -d /home/app app

# copy requirements + install as root (pip cache can be shared)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# copy app and set ownership to non-root user
COPY . /app
RUN chown -R app:app /app

USER app
WORKDIR /app

EXPOSE 8501

# Use query param health check (streamlit doesn't expose /healthz)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -fsS "http://localhost:8501/?healthz=1" || exit 1

CMD ["streamlit", "run", "app/main.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true"]
