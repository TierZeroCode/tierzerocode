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

# Copy application code and startup script
COPY --chown=appuser:appuser . .
COPY --chown=appuser:appuser start.sh /app/start.sh
RUN chmod +x /app/start.sh

# Create static directory and collect static files
RUN mkdir -p /app/static && \
    chown -R appuser:appuser /app/static && \
    python manage.py collectstatic --noinput || true

# --- CRITICAL FIX FOR LOG PERMISSIONS ---
# Create the log file as root, then hand ownership to appuser
# This ensures FileHandler doesn't fail with Permission Denied
RUN touch /app/tierzerocode.log && \
    chown appuser:appuser /app/tierzerocode.log && \
    chmod 664 /app/tierzerocode.log
# ----------------------------------------

# Switch to non-root user
USER appuser

# Expose the application port
EXPOSE 8000 

# Start both gunicorn and rqworker using the startup script
CMD ["/app/start.sh"]