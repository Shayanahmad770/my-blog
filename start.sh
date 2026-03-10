#!/bin/bash

# Print startup banner
echo "==================================="
echo "  Starting Blog Application"
echo "==================================="
echo "Using database: ${DATABASE_URL:0:50}..."

# Check if this is first run (database needs initialization)
if [ ! -f ".db_initialized" ]; then
    echo "First run detected - initializing database..."
    python deploy_init.py && touch .db_initialized
else
    echo "Database already initialized"
fi

# Start the application
echo "Starting Gunicorn server..."
exec gunicorn --bind 0.0.0.0:8080 app:app