FROM python:3.12-slim

# Environment settings for reliable runtime behavior
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install system deps (curl used by health checks; build tools if needed)
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first to leverage Docker layer caching
COPY apps/api/requirements.txt apps/api/requirements.txt
RUN pip install --upgrade pip \
    && pip install -r apps/api/requirements.txt

# Copy the entire repository
COPY . .

# Expose Flask port
EXPOSE 8080

# Ensure the repo root is importable
ENV PYTHONPATH=/app

# Default command: run API server
CMD ["python", "apps/api/main.py"]


