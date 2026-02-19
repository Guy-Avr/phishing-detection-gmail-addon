"""
Update OpenPhish feed into the phish URL DB. Run every 12 hours (cron/Task Scheduler).

Usage (from backend directory):
  python -m app.tasks.update_phish_feed
"""

import sys

from app.reputation.openphish import update_phish_db
from app.settings import settings


def main() -> int:
    db_path = settings.phish_db_path
    try:
        count, last_updated = update_phish_db(db_path)
        print(f"Updated phish DB: {count} URLs, last_updated={last_updated}")
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
