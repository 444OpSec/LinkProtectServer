# Hypercorn developement run config

# run: hypercorn -c file:hypercorn_dev.py app.main:app --reload

# reloading doesn't work on Windows

import sys

bind = "127.0.0.1:8000"

loglevel = "debug"
accesslog = "-"
errorlog = "-"
workers = 1
