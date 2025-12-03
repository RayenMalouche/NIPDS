# docker/Dockerfile - Main NIDS+NIPS API Service

FROM python:3.11-slim

LABEL maintainer="rayen.malouche@gmail.com"
LABEL description="Network Intrusion Detection & Prevention System - API Service"
LABEL version="2.0"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpcap-dev \
    tcpdump \
    curl \
    wget \
    net-tools \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY config/ ./config/

# Create necessary directories
RUN mkdir -p /app/models \
             /app/logs \
             /app/datasets \
             /app/alerts \
             /app/reports

# Set Python path
ENV PYTHONPATH=/app/src

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/ || exit 1

# Run application
CMD ["python", "src/main.py"]