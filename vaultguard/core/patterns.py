import re
from typing import Dict, List, Tuple

# Pattern tuple: (rule_id, name, regex, severity, entropy_check)
SECRET_RULES: List[Tuple[str, str, re.Pattern, str, bool]] = [
    (
        "VG-AWS-001",
        "AWS Access Key ID",
        re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
        "CRITICAL",
        False
    ),
    (
        "VG-AWS-002",
        "AWS Secret Access Key",
        re.compile(r'(?i)aws_secret_access_key\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
        "CRITICAL",
        True
    ),
    (
        "VG-GH-001",
        "GitHub Personal Access Token",
        re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{30,255})\b'),
        "CRITICAL",
        False
    ),
    (
        "VG-OPENAI-001",
        "OpenAI API Key",
        re.compile(r'\b(sk-[A-Za-z0-9]{20,64})\b'),
        "CRITICAL",
        True
    ),
    (
        "VG-GCP-001",
        "Google Cloud API Key",
        re.compile(r'\b(AIzaSy[A-Za-z0-9_-]{33})\b'),
        "CRITICAL",
        False
    ),
    (
        "VG-SLACK-001",
        "Slack Webhook URL",
        re.compile(r'https://hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8,12}/[0-9A-Za-z]{24}'),
        "HIGH",
        False
    ),
    (
        "VG-STRIPE-001",
        "Stripe Secret Key",
        re.compile(r'\b(sk_live_[0-9a-zA-Z]{20,34})\b'),
        "CRITICAL",
        False
    ),
    (
        "VG-SSH-001",
        "Private Cryptographic Key",
        re.compile(r'-----BEGIN (?:RSA|DSA|EC|OPENSSH|PRIVATE) KEY-----'),
        "CRITICAL",
        False
    ),
    (
        "VG-DB-001",
        "Database Connection String with Credentials",
        re.compile(r'(?i)(?:postgres|postgresql|mysql|mongodb|redis)://[a-zA-Z0-9_\-\.]+:[^@\s]+@[a-zA-Z0-9_\-\.]+:\d+/[a-zA-Z0-9_\-\.]+'),
        "HIGH",
        False
    )
]
