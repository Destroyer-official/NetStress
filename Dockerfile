# Advanced DDoS Testing Framework - Docker Image
# Multi-stage build for optimized production image

# Build stage
FROM python:3.11-slim as builder

# Set build arguments
ARG BUILD_DATE
ARG VERSION=1.0.0
ARG VCS_REF

# Set labels
LABEL maintainer="DDoS Framework Team <team@ddos-framework.org>"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.name="Advanced DDoS Testing Framework"
LABEL org.label-schema.description="World-class cybersecurity testing platform"
LABEL org.label-schema.url="https://github.com/ddos-framework/advanced-ddos-framework"
LABEL org.label-schema.vcs-ref=$VCS_REF
LABEL org.label-schema.vcs-url="https://github.com/ddos-framework/advanced-ddos-framework"
LABEL org.label-schema.vendor="DDoS Framework Team"
LABEL org.label-schema.version=$VERSION
LABEL org.label-schema.schema-version="1.0"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpcap-dev \
    libffi-dev \
    libssl-dev \
    pkg-config \
    gcc \
    g++ \
    make \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
COPY setup.py .
COPY pyproject.toml .
COPY MANIFEST.in .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Build and install the framework
RUN pip install --no-cache-dir -e .

# Production stage
FROM python:3.11-slim as production

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libffi8 \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r ddos && useradd -r -g ddos -d /app -s /bin/bash ddos

# Set working directory
WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --from=builder /app /app

# Create necessary directories
RUN mkdir -p /app/config /app/logs /app/data /app/results /app/cache \
    && chown -R ddos:ddos /app

# Copy configuration files
COPY config/docker_config.yaml /app/config/config.yaml

# Switch to non-root user
USER ddos

# Set environment variables
ENV PYTHONPATH=/app
ENV DDOS_CONFIG_DIR=/app/config
ENV DDOS_LOG_DIR=/app/logs
ENV DDOS_DATA_DIR=/app/data

# Expose ports
EXPOSE 8000 8080 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command
CMD ["ddos-framework", "--mode", "api"]

# Development stage
FROM production as development

# Switch back to root for development tools
USER root

# Install development dependencies
RUN pip install --no-cache-dir pytest pytest-asyncio pytest-cov black flake8 mypy

# Install additional development tools
RUN apt-get update && apt-get install -y \
    vim \
    htop \
    net-tools \
    tcpdump \
    wireshark-common \
    && rm -rf /var/lib/apt/lists/*

# Switch back to ddos user
USER ddos

# Development command
CMD ["ddos-framework", "--mode", "interactive"]