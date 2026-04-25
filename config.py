"""
Configuration for certificate expiry notifications to MAX.

This file is intentionally committed to the repository as a template.
Fill in sensitive values on your server before running.
"""

# Bot token from MAX platform
MAX_ACCESS_TOKEN = ""

# Target chat id (group or direct chat), for example: -73951350663826
CHAT_ID = ""

# Root folders for recursive certificate search
CERT_ROOTS = [
    "/opt/bot_cert/certs",
]

# Supported certificate file extensions
ALLOWED_EXTENSIONS = {".crt", ".cer", ".pem"}

# Planned alert thresholds in days before expiry
ALERT_THRESHOLDS = [60, 30, 14, 7]

# Cache path for deduplication and pending messages
CACHE_FILE = "/opt/bot_cert/sent_cache.json"

# MAX API settings
MAX_MESSAGES_URL = "https://platform-api.max.ru/messages"
MAX_REQUEST_TIMEOUT = 10

# Working hours (local server time): [start, end)
WORK_HOUR_START = 9
WORK_HOUR_END = 21

# Test mode:
# True  -> send alert on every run, ignore cache and working hours.
# False -> normal production behavior.
FORCE_SEND_EVERY_RUN = False
