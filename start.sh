#!/bin/sh
set -e

# Wait for database to be ready
echo "Waiting for database..."
while ! python -c "
import os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tierzerocode.settings')
import django; django.setup()
from django.db import connections
try:
    connections['default'].cursor()
except Exception:
    sys.exit(1)
" 2>/dev/null; do
    echo "Database not ready, retrying in 2s..."
    sleep 2
done
echo "Database is ready."

# Run migrations
echo "Running migrations..."
python manage.py migrate --noinput
echo "Migrations complete."

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --noinput
echo "Static files collected."

# Start the requested service (default: gunicorn)
exec "$@"
