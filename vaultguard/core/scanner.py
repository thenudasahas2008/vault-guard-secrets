import os
from typing import List, Generator
from vaultguard.core.patterns import SECRET_RULES
from vaultguard.core.entropy import calculate_shannon_entropy
from vaultguard.core.models import SecretFinding

class SecretScanner:
    IGNORE_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".tar", ".gz",
        ".lock", ".sqlite", ".db", ".exe", ".dll", ".so", ".pyc"
    }
    IGNORE_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache"}

    @staticmethod
    def mask_secret(secret_str: str) -> str:
        if len(secret_str) <= 6:
            return "*" * len(secret_str)
        return secret_str[:3] + ("*" * (len(secret_str) - 6)) + secret_str[-3:]

    def scan_text(self, text: str, file_path: str = "inline") -> List[SecretFinding]:
        findings = []
        lines = text.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            # Skip excessively long lines (minified JS etc)
            if len(line) > 1000:
                continue

            for rule_id, rule_name, pattern, severity, check_entropy in SECRET_RULES:
                match = pattern.search(line)
                if match:
                    raw_match = match.group(1) if match.groups() else match.group(0)
                    entropy = calculate_shannon_entropy(raw_match)

                    # If entropy check is requested, ensure threshold met
                    if check_entropy and entropy < 3.2:
                        continue

                    findings.append(SecretFinding(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        file_path=file_path,
                        line_number=line_idx,
                        matched_text_masked=self.mask_secret(raw_match),
                        severity=severity,
                        entropy=entropy,
                        remediation=f"Remove secret from source code; store in environment variables or key vault, and revoke compromised credential."
                    ))

        return findings

    def scan_file(self, file_path: str) -> List[SecretFinding]:
        ext = os.path.splitext(file_path)[1].lower()
        if ext in self.IGNORE_EXTENSIONS:
            return []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return self.scan_text(content, file_path)
        except Exception:
            return []

    def scan_directory(self, dir_path: str) -> List[SecretFinding]:
        findings = []
        for root, dirs, files in os.walk(dir_path):
            dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS]
            for file in files:
                full_path = os.path.join(root, file)
                findings.extend(self.scan_file(full_path))
        return findings
