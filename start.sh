#!/bin/sh
# Start script to run both gunicorn and rqworker

# Start gunicorn in the background with increased timeout for long-running exports
python -m gunicorn --bind 0.0.0.0:8000 --workers 3 --timeout 300 tierzerocode.wsgi:application &

# Start rqworker in the background with scheduler
# The scheduler will handle repeating jobs scheduled via Repeat class
python manage.py rqworker default --job-class django_tasks_rq.Job --with-scheduler &

# Wait for all background processes
wait

