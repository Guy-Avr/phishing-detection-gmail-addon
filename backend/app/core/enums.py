"""All application enums in a single place."""

from enum import Enum


class Verdict(str, Enum):
    """Final detection label."""

    SAFE = "Safe"
    SUSPICIOUS = "Suspicious"
    PHISHING = "Phishing"
