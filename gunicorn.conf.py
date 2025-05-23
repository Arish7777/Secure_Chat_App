import multiprocessing

# Gunicorn configuration for production
bind = "0.0.0.0:8000"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "eventlet"
timeout = 120
keepalive = 5
accesslog = "-"
errorlog = "-"
loglevel = "info" 