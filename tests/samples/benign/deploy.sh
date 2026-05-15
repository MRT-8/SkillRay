#!/bin/bash
# Legitimate deployment script
set -euo pipefail

echo "Starting deployment..."

# Install dependencies
pip install -r requirements.txt

# Run database migrations
python manage.py migrate

# Collect static files
python manage.py collectstatic --noinput

# Restart the service
echo "Restarting myapp service..."

echo "Deployment complete!"
