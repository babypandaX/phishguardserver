#!/bin/bash
gunicorn app:app --workers 1 --bind 0.0.0.0:$PORT
