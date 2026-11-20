from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class SecretFinding:
    rule_id: str
    rule_name: str
    file_path: str
    line_number: int
    matched_text_masked: str
    severity: str
    entropy: float
    remediation: str
