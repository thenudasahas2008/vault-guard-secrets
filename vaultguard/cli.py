import argparse
import sys
import os
from vaultguard.core.scanner import SecretScanner
from vaultguard.core.git_hook import GitHookInstaller

def main():
    parser = argparse.ArgumentParser(
        description="VaultGuard — Pre-commit Cryptographic Secret & API Key Leak Scanner"
    )
    parser.add_argument("path", nargs="?", default=".", help="Directory or file path to scan")
    parser.add_argument("--install-hook", action="store_true", help="Install pre-commit hook in local .git repo")
    args = parser.parse_args()

    if args.install_hook:
        try:
            path = GitHookInstaller.install(".")
            print(f"[+] VaultGuard git pre-commit hook installed successfully at: {path}")
            sys.exit(0)
        except Exception as e:
            print(f"[!] Error: {e}")
            sys.exit(1)

    print("="*65)
    print("VAULTGUARD // CRYPTOGRAPHIC SECRET SCANNER")
    print("="*65)
    print(f"[*] Scanning path: {args.path}")

    scanner = SecretScanner()
    if os.path.isfile(args.path):
        findings = scanner.scan_file(args.path)
    else:
        findings = scanner.scan_directory(args.path)

    if not findings:
        print("[+] Scan complete. Zero secrets or API keys detected! Repository clean.")
        sys.exit(0)
    else:
        print(f"\n[!] WARNING: {len(findings)} potential secret leaks detected!\n")
        for f in findings:
            print(f"  [{f.severity}] {f.rule_name} (ID: {f.rule_id})")
            print(f"  Location: {f.file_path}:{f.line_number}")
            print(f"  Masked:   {f.matched_text_masked} (Shannon Entropy: {f.entropy})")
            print(f"  Fix:      {f.remediation}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
