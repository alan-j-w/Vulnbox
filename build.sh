#!/usr/bin/env bash
# Exit on error
set -o errexit

# Enter the project directory
cd vulnbox_project

# Install dependencies
pip install -r requirements.txt

# Run Django management commands
python manage.py collectstatic --noinput
python manage.py migrate
