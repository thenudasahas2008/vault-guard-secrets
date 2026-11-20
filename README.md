# VaultGuard — Pre-commit Cryptographic Secret & API Key Leak Prevention Engine

[![Security: Secret Scanner](https://img.shields.io/badge/Security-Secret%20Scanner-red.svg)](#)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#)

VaultGuard is a developer-first security tool engineered to intercept uncommitted API tokens, private cryptographic keys, database credentials, and high-entropy secrets before they ever reach a remote version control system.

---

## Key Capabilities

- **25+ Pre-configured Secret Signatures**:
  - AWS Access Key ID (`AKIA...`) and Secret Access Keys
  - GitHub Personal Access Tokens (`ghp_`, `gho_`, `github_pat_`)
  - Slack API Bot Tokens and Incoming Webhooks
  - Stripe Live and Test Secret Keys (`sk_live_`, `sk_test_`)
  - Google Cloud API Keys and Service Account JSON credentials
  - Asymmetric Private Keys (RSA, DSA, EC, OPENSSH)
  - Generic High-Entropy Passwords & Connection Strings
- **Shannon Entropy Evaluation**: Calculates character distribution randomness ($H \ge 4.5$) to catch custom or unformatted secret tokens that escape static regex rules.
- **Native Git Pre-commit Hook**: Installs directly into `.git/hooks/pre-commit` to automatically block commits containing leaked secrets.
- **Safe Output Masking**: Automatically redacts matched secrets in CLI output (`AKIA****************`) to prevent secondary disclosure.

---

## Installation & Setup

```bash
# Clone the repository
git clone https://github.com/thenudasahas2008/vault-guard-secrets.git
cd vault-guard-secrets

# Install dependencies and local CLI entry point
pip install -e .
```

---

## CLI Usage

### 1. Scan Current Repository or Directory
```bash
# Scan working directory
vaultguard .

# Scan specific directory or configuration file
vaultguard samples/leaked_config.env
```

### 2. Install Native Git Hook
```bash
# Enforce pre-commit scanning across the local repository
vaultguard --install-hook
```
Once installed, any `git commit` command that introduces a secret will be rejected automatically.

---

## Automated Verification & Testing

```bash
# Run pytest verification suite
pytest -v tests
```

---

## Repository Structure

```
vault-guard-secrets/
├── vaultguard/
│   ├── core/
│   │   ├── entropy.py       # Shannon entropy mathematical calculator
│   │   ├── git_hook.py      # Git hook installer and execution wrapper
│   │   ├── models.py        # Pydantic schemas for findings and rules
│   │   ├── patterns.py      # 25+ Regular expression secret signatures
│   │   └── scanner.py       # Multi-file and directory traversal scanner
│   └── cli.py               # Command-line interface
├── samples/                 # Sample decoy files for testing
└── tests/                   # Pytest test cases
```
