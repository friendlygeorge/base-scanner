# base-scanner

A lightweight on-chain security scanner for Base chain smart contracts. Fetches verified source code from Sourcify, runs pattern-based security analysis, and generates human-readable reports.

![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)

## Features

- **No API key required** — uses Sourcify (free) for source code verification
- **15 security checks** covering the most common vulnerability patterns
- **Clean markdown reports** with severity ratings and evidence
- **JSON output** for programmatic use
- **Multi-chain ready** — works on Base (default) and any EVM chain supported by Sourcify

## Security Checks

| Check | Severity | What it detects |
|-------|----------|-----------------|
| Reentrancy | MEDIUM | External calls followed by state changes without guards |
| Access Control | HIGH | Admin functions without access control patterns |
| Unchecked Calls | LOW | Low-level calls without return value checks |
| tx.origin | MEDIUM | Use of tx.origin for authorization |
| Selfdestruct | MEDIUM | Contract can be destroyed |
| Delegatecall | HIGH/INFO | Delegatecall usage (high if user-controlled) |
| Timestamp Dependence | LOW | Heavy block.timestamp usage |
| Integer Overflow | MEDIUM | Missing SafeMath on pre-0.8.0 compilers |
| Flash Loan | INFO | Oracles used with deposit/swap functions |
| Oracle Manipulation | INFO | Single-block price reads |
| Upgradeable | MEDIUM/INFO | Proxy patterns (medium without timelock) |
| Centralization | LOW | Single owner without multisig |
| Missing Events | INFO | State changes without event emissions |
| Gas Griefing | MEDIUM | Unbounded loops over dynamic arrays |
| First Deposit | MEDIUM | ERC-4626 vault without inflation protection |

## Installation

```bash
pip install .
```

Or install from source:

```bash
git clone https://github.com/friendlygeorge/base-scanner
cd base-scanner
pip install -e .
```

## Usage

### CLI

```bash
# Scan a contract on Base (default)
base-scanner 0xA238Dd80C259a72e81d7e4664a9801593F98d1c5

# Output as JSON
base-scanner 0xA238Dd80C259a72e81d7e4664a9801593F98d1c5 --json

# Save report to file
base-scanner 0xA238Dd80C259a72e81d7e4664a9801593F98d1c5 -o report.md

# Scan on a different chain
base-scanner 0x... --chain-id 1  # Ethereum mainnet
```

### Python

```python
from base_scanner import SecurityScanner

scanner = SecurityScanner("0xA238Dd80C259a72e81d7e4664a9801593F98d1c5")
result = scanner.scan()

print(f"Found {result['summary']['total']} findings")
print(f"  High: {result['summary']['high']}")
print(f"  Medium: {result['summary']['medium']}")
print(f"  Low: {result['summary']['low']}")
```

## Output Format

### Markdown (default)

```markdown
# Security Scan Report

**Contract:** USDC (0xA238Dd80C259a72e81d7e4664a9801593F98d1c5)
**Compiler:** ^0.8.17
**Scan Time:** 2026-06-06T12:00:00+00:00

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 1 |
| 🔵 Low | 2 |
| ⚪ Info | 3 |
| **Total** | **6** |
```

### JSON

```json
{
  "address": "0xa238dd80c259a72e81d7e4664a9801593f98d1c5",
  "contract_name": "USDC",
  "compiler": "^0.8.17",
  "chain_id": 8453,
  "summary": {
    "total": 6,
    "critical": 0,
    "high": 0,
    "medium": 1,
    "low": 2,
    "info": 3
  },
  "findings": [...]
}
```

## How It Works

1. **Bytecode check** — Verifies the address has deployed code
2. **Source fetch** — Pulls verified source from Sourcify (free, no API key)
3. **Pattern analysis** — Runs 15 regex-based security checks against the source
4. **Report generation** — Outputs findings sorted by severity

## Limitations

- **Pattern-based only** — This is not a formal verification tool or a substitute for manual audit
- **Source-dependent** — Only works on verified contracts
- **No economic analysis** — Does not check for MEV, oracle manipulation economics, or complex DeFi attack vectors
- **Regex false positives** — Some findings may be false positives; always review manually

For comprehensive security analysis, use tools like [Slither](https://github.com/crytic/slither), [Mythril](https://github.com/ConsenSys/mythril), or hire a professional auditor.

## Requirements

- Python 3.9+
- `requests`
- `web3`

## License

MIT

## Contributing

Contributions welcome! Open an issue or PR at [github.com/friendlygeorge/base-scanner](https://github.com/friendlygeorge/base-scanner).
