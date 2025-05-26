#!/bin/bash
set -o errexit  # Exit on any error

# 1. Install dependencies
pip install -r requirements.txt
pip install gunicorn

# 2. Apply database migrations (production only)
if [ -n "$RENDER" ]; then
  echo "-> Running database migrations"
  flask db upgrade
fi