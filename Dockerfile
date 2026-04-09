# Stage 1: Base build stage
FROM hub.awbtech.org/dhi-registry/python:3-alpine3.23-dev AS builder

WORKDIR /app

# Set environment variables to optimize Python
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Upgrade pip and install dependencies
RUN pip install --upgrade pip
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy site-packages to a known location for production stage
RUN SITE_PKG=$(python3 -c "import site; print(site.getsitepackages()[0])") && \
    cp -r "$SITE_PKG" /tmp/builder-packages

# ---

# Stage 2: Production stage
FROM hub.awbtech.org/dhi-registry/python:3-alpine3.23-dev

# Create non-root user and app directory
RUN adduser -D -s /bin/sh appuser && \
    mkdir /app && \
    chown -R appuser /app

# Copy Python dependencies from builder stage
COPY --from=builder /tmp/builder-packages /tmp/builder-packages
RUN SITE_PKG=$(python3 -c "import site; print(site.getsitepackages()[0])") && \
    mkdir -p "$(dirname "$SITE_PKG")" && \
    cp -r /tmp/builder-packages/* "$SITE_PKG"/ && \
    rm -rf /tmp/builder-packages

WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Copy application code
COPY --chown=appuser:appuser . .

# Download Tailwind CSS standalone CLI
RUN wget -qO tailwindcss https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64-musl \
    && chmod +x tailwindcss

# Build Tailwind CSS
RUN ./tailwindcss -i apps/main/static/main/css/tailwind-input.css -o apps/main/static/main/css/tailwind-output.css --minify

# Create static and log directories with correct permissions
RUN mkdir -p /app/static && \
    chown -R appuser:appuser /app/static && \
    touch /app/tierzerocode.log && \
    chown appuser:appuser /app/tierzerocode.log && \
    chmod 664 /app/tierzerocode.log

# Switch to non-root user
USER appuser

# Expose the application port
EXPOSE 8000

# Default command — docker-compose.yml overrides with migrate + collectstatic prefixed
CMD ["python", "-m", "gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "300", "tierzerocode.wsgi:application"]
