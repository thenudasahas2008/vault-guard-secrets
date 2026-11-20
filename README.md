# VaultGuard Secrets

Automated pre-commit secret leak prevention engine built in Python.

## Core Capabilities
- Pattern detection across 25+ API key, credential, and private key formats.
- Shannon entropy evaluation to catch high-randomness credentials and tokens.
- Native Git pre-commit hook integration to halt uncommitted secret leakage.
- Deterministic masking and severity classification.

## Quickstart

```bash
pip install -e .
vaultguard .
vaultguard --install-hook
```
