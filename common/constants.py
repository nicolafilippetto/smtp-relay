"""Cross-service constants.

These values are deliberately hard-coded in source (not environment
variables and not DB columns) because they represent security-sensitive
floors that must not be bypassable through the UI, the REST API, a
cron hook, or environment-variable tampering.

If an operator needs to relax them they must edit this file, rebuild
the image, and redeploy — a high-friction path by design.
"""

# -----------------------------------------------------------------------------
# Retention floors
# -----------------------------------------------------------------------------
# Mail archive: minimum 3 days.
#
# Rationale: in the event of an account compromise an attacker with UI
# access should not be able to truncate the archive instantly. Three days
# gives operations staff enough time to notice suspicious activity, pull
# the volume, and preserve evidence before the cron pruner removes data.
ARCHIVE_RETENTION_MIN_DAYS = 3
ARCHIVE_RETENTION_DEFAULT_DAYS = 30

# Audit log: minimum 30 days.
#
# Rationale: audit logs must survive long enough to reconstruct an
# incident timeline. Shorter retention would defeat the purpose of
# having an audit trail at all.
AUDIT_RETENTION_MIN_DAYS = 30
AUDIT_RETENTION_DEFAULT_DAYS = 90

# Sent-mail queue rows: default 30 days, no enforced minimum (the
# authoritative record is the archive, not the queue row).
QUEUE_SENT_RETENTION_DEFAULT_DAYS = 30

# -----------------------------------------------------------------------------
# SMTP auth ban defaults
# -----------------------------------------------------------------------------
SMTP_BAN_THRESHOLD_DEFAULT = 5
SMTP_BAN_DURATION_MIN_DEFAULT = 30

# -----------------------------------------------------------------------------
# Queue retry policy
# -----------------------------------------------------------------------------
QUEUE_MAX_ATTEMPTS_DEFAULT = 3
# Backoff schedule in seconds; index is (attempt - 1). If attempts exceed
# the length, the last value is reused.
QUEUE_BACKOFF_SECONDS = [60, 300, 900]

# -----------------------------------------------------------------------------
# Bcrypt cost factor
# -----------------------------------------------------------------------------
# Must be >= 12 per the spec. Kept as a constant so both services hash
# identically and so audits can easily grep for the value.
BCRYPT_COST_FACTOR = 12

# -----------------------------------------------------------------------------
# Graph API
# -----------------------------------------------------------------------------
GRAPH_AUTHORITY_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}"
GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]
GRAPH_SEND_MAIL_URL = "https://graph.microsoft.com/v1.0/users/{sender}/sendMail"
GRAPH_HTTP_TIMEOUT_SECONDS = 30
