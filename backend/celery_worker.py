"""Celery worker entry point"""
import sys
import os

# Add the backend directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.celery_app import celery_app

# This allows running the worker with: celery -A celery_worker worker
if __name__ == "__main__":
    celery_app.start()
