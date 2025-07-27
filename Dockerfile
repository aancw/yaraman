# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies required for YARA and build tools
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    autoconf \
    automake \
    libtool \
    pkg-config \
    flex \
    bison \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r yaraman && useradd -r -g yaraman -s /bin/bash yaraman

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create necessary directories and set permissions
RUN mkdir -p uploads yara_rules \
    && chown -R yaraman:yaraman /app

# Switch to non-root user
USER yaraman

# Expose the application port
EXPOSE 5002

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PYTHONPATH=/app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5002')" || exit 1

# Run the application
CMD ["python", "app.py"]