FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/dwizzzle/psychiq-webapp"
LABEL org.opencontainers.image.description="PSYCHIQ Vulnerable Web App - Enterprise Adversary Gym"

WORKDIR /app

# Install ping for the diagnostics endpoint
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping curl && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/uploads /app/data

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8080/health || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--access-logfile", "-", "app:app"]
