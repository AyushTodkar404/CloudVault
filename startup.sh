#!/bin/bash
# Azure App Service Linux Startup Script for CloudVault
echo "Starting CloudVault Gunicorn production server..."
gunicorn --bind=0.0.0.0 --timeout 600 "app:create_app()"
