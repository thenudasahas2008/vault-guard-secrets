import os
import stat
import sys

HOOK_SCRIPT = """#!/usr/bin/env python
import sys
import subprocess
from vaultguard.core.scanner import SecretScanner

def main():
    # Get staged files
    cmd = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, text=True)
    staged_files = [f.strip() for f in res.stdout.splitlines() if f.strip()]

    scanner = SecretScanner()
    leaks_found = []

    for f_path in staged_files:
        findings = scanner.scan_file(f_path)
        if findings:
            leaks_found.extend(findings)

    if leaks_found:
        print("\\n[!] VAULTGUARD PRE-COMMIT BLOCKED: Plaintext secrets detected in commit!")
        print("="*70)
        for leak in leaks_found:
            print(f"  - [{leak.severity}] {leak.rule_name} in {leak.file_path}:{leak.line_number}")
            print(f"    Secret: {leak.matched_text_masked} (Entropy: {leak.entropy})")
        print("="*70)
        print("[*] Please remove secrets from source code before committing.")
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
"""

class GitHookInstaller:
    @staticmethod
    def install(repo_root: str = "."):
        hooks_dir = os.path.join(repo_root, ".git", "hooks")
        if not os.path.exists(hooks_dir):
            raise FileNotFoundError(f"Not a git repository: {hooks_dir} not found.")

        hook_path = os.path.join(hooks_dir, "pre-commit")
        with open(hook_path, "w", encoding="utf-8") as f:
            f.write(HOOK_SCRIPT)

        # Make executable
        st = os.stat(hook_path)
        os.chmod(hook_path, st.st_mode | stat.S_IEXEC)
        return hook_path
