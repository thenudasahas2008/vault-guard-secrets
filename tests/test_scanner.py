from pathlib import Path
root = Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0, str(root))

from vaultguard.core.scanner import SecretScanner
from vaultguard.core.entropy import calculate_shannon_entropy

def test_entropy_calculation():
    # Low entropy repeating string
    low_ent = calculate_shannon_entropy("aaaaaaaaaaaa")
    assert low_ent == 0.0

    # High entropy API key
    high_ent = calculate_shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    assert high_ent > 4.0

def test_sample_file_secrets_detection():
    scanner = SecretScanner()
    sample_file = root / "samples" / "leaked_config.env"
    assert sample_file.exists()

    findings = scanner.scan_file(str(sample_file))
    assert len(findings) >= 4

    rules = [f.rule_id for f in findings]
    assert "VG-AWS-001" in rules
    assert "VG-GH-001" in rules
    assert "VG-STRIPE-001" in rules
    assert "VG-DB-001" in rules

    # Verify masking
    for f in findings:
        assert "****" in f.matched_text_masked
