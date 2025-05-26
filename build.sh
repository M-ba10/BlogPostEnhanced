#!/bin/bash
# Exit immediately on errors
set -o errexit

# 1. Install dependencies
pip install -r requirements.txt

# 2. Only run database migrations in production (Render)
if [ "$RENDER" ]; then
  echo "-> Running database migrations in production"
  flask db upgrade
else
  echo "-> Skipping migrations (not in production)"
fi

# 3. Collect static files (if using Flask-Assets or similar)
# echo "-> Collecting static files"
# flask assets build