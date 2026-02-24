# Hypercorn release run config (UNIX ONLY)

import multiprocessing
import os

workers = min(multiprocessing.cpu_count() + 1, 8) # CPU_CORES+1, max=8

bind = "0.0.0.0:8000"

loop = "uvloop"

loglevel = os.getenv("APP_LOG_LEVEL", "info")
#accesslog = "-"
errorlog = "-"
