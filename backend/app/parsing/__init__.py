# Parsing: email parsing and link extraction. Rules use ParsedEmail only.
# All HTML/email splitting happens in the backend (raw_parser + email_parser).

from app.parsing.email_parser import ParsedEmail, parse_email, parse_raw_email

__all__ = ["ParsedEmail", "parse_email", "parse_raw_email"]
