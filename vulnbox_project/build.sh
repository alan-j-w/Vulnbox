#!/usr/bin/env bash
# Exit on error
set -o errexit

# Since Root Directory is set to vulnbox_project, we are already in the right place!
pip install -r requirements.txt

python manage.py collectstatic --noinput
python manage.py migrate
