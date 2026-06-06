"""
Core scanner module — scans Base chain contracts for common security issues.

Usage:
    from base_scanner import SecurityScanner

    scanner = SecurityScanner("0x...")
    result = scanner.scan()
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Optional

import requests

SOURCIFY_API = "https://sourcify.dev/server"

# Optional: Alchemy for bytecode fallback
ALCHEMY_KEY = os.environ.get("ALCHEMY_API_KEY", "")
ALCHEMY_RPC = f"https://base-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}" if ALCHEMY_KEY else ""


class SecurityScanner:
    """Scans a Base contract for common security issues."""

    def __init__(self, address: str, chain_id: int = 8453):
        """
        Initialize scanner.

        Args:
            address: Contract address to scan (checksummed or not)
            chain_id: Chain ID (default: 8453 for Base)
        """
        self.address = address.lower()
        self.chain_id = chain_id
        self.address_checksum = self._to_checksum(address)
        self.findings = []
        self.info = {}
        self.source_code = None
        self.compiler_version = None
        self.contract_name = None

    @staticmethod
    def _to_checksum(address: str) -> str:
        """Convert to checksummed address."""
        from web3 import Web3
        return Web3.to_checksum_address(address)

    def scan(self) -> dict:
        """Run full scan and return results."""
        print(f"[*] Scanning {self.address_checksum}...", file=sys.stderr)

        if not self._check_contract_exists():
            return self._error("No bytecode found at this address")

        if not self._fetch_source():
            return self._error("Could not fetch source code (contract may not be verified)")

        self._check_reentrancy()
        self._check_access_control()
        self._check_unchecked_calls()
        self._check_tx_origin()
        self._check_selfdestruct()
        self._check_delegatecall()
        self._check_timestamp_dependence()
        self._check_integer_overflow()
        self._check_flash_loan_exposure()
        self._check_oracle_manipulation()
        self._check_upgradeable()
        self._check_centralization()
        self._check_missing_events()
        self._check_gas_griefing()
        self._check_first_deposit_attack()

        return self._generate_report()

    def _check_contract_exists(self) -> bool:
        """Verify bytecode exists at address."""
        try:
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(ALCHEMY_RPC or "https://mainnet.base.org"))
            code = w3.eth.get_code(self.address_checksum)
            self.info["has_bytecode"] = len(code) > 2
            self.info["bytecode_size"] = len(code)
            return self.info["has_bytecode"]
        except Exception as e:
            print(f"[!] Error checking bytecode: {e}", file=sys.stderr)
            return False

    def _fetch_source(self) -> bool:
        """Fetch verified source code from Sourcify (free, no API key)."""
        try:
            url = f"{SOURCIFY_API}/files/any/{self.chain_id}/{self.address}"
            resp = requests.get(url, timeout=15)
            data = resp.json()

            files = data.get("files", [])
            if not files:
                return False

            sol_files = [f for f in files if f.get("name", "").endswith(".sol")]
            if not sol_files:
                return False

            sol_files.sort(key=lambda x: len(x.get("content", "")), reverse=True)

            all_source = []
            for f in files:
                name = f.get("name", "unknown")
                content = f.get("content", "")
                if content:
                    all_source.append(f"// File: {name}\n{content}")

            self.source_code = "\n\n".join(all_source)

            main_file = sol_files[0]
            self.contract_name = main_file.get("name", "unknown").replace(".sol", "")

            pragma_match = re.search(r'pragma solidity\s+([^;]+)', self.source_code)
            if pragma_match:
                self.compiler_version = pragma_match.group(1).strip()
            else:
                self.compiler_version = "unknown"

            self.info["compiler"] = self.compiler_version
            self.info["contract_name"] = self.contract_name
            self.info["source_files"] = len(files)
            self.info["is_proxy"] = any(
                "proxy" in f.get("name", "").lower() for f in files
            )

            return True
        except Exception as e:
            print(f"[!] Error fetching source: {e}", file=sys.stderr)
            return False

    def _add_finding(self, severity: str, category: str, title: str, description: str, evidence: str = ""):
        """Add a security finding."""
        self.findings.append({
            "severity": severity,
            "category": category,
            "title": title,
            "description": description,
            "evidence": evidence[:200] if evidence else "",
        })

    def _check_reentrancy(self):
        """Check for reentrancy patterns."""
        if not self.source_code:
            return

        external_call_pattern = re.compile(
            r'\.call\{.*\}\(|\.call\.value\(|\.transfer\(|\.send\('
        )
        state_change_pattern = re.compile(
            r'storage\[|mapping\[.*\]\[.*\]\s*=|balances\[|totalSupply\s*='
        )

        calls = external_call_pattern.findall(self.source_code)
        state_changes = state_change_pattern.findall(self.source_code)

        if calls and state_changes:
            has_guard = bool(re.search(
                r'nonReentrant|ReentrancyGuard|reentrancyGuard|_reentrancyGuard',
                self.source_code
            ))
            if not has_guard:
                self._add_finding(
                    "MEDIUM",
                    "Reentrancy",
                    "Potential reentrancy vulnerability",
                    f"Found {len(calls)} external call(s) and {len(state_changes)} state change(s) "
                    f"without a reentrancy guard.",
                    str(calls[:3])
                )
            else:
                self.info["has_reentrancy_guard"] = True

    def _check_access_control(self):
        """Check for missing access control."""
        if not self.source_code:
            return

        admin_functions = re.findall(
            r'function\s+(\w*(?:admin|owner|withdraw|mint|burn|pause|upgrade|set|configure)\w*)\s*\(',
            self.source_code,
            re.IGNORECASE
        )

        has_access_control = bool(re.search(
            r'onlyOwner|onlyAdmin|require\s*\(\s*msg\.sender\s*==|AccessControl|hasRole|canCall',
            self.source_code
        ))

        if admin_functions and not has_access_control:
            self._add_finding(
                "HIGH",
                "Access Control",
                "Admin functions without access control",
                f"Found {len(admin_functions)} admin-like functions without access control. "
                f"Functions: {', '.join(admin_functions[:5])}",
            )

    def _check_unchecked_calls(self):
        """Check for unchecked low-level calls."""
        if not self.source_code:
            return

        pattern = re.compile(r'\.call\{[^}]*\}\([^)]*\)\s*;')
        unchecked = pattern.findall(self.source_code)

        if unchecked:
            self._add_finding(
                "LOW",
                "Unchecked Call",
                "Unchecked low-level call",
                f"Found {len(unchecked)} low-level call(s) that may not check return values.",
                str(unchecked[:3])
            )

    def _check_tx_origin(self):
        """Check for tx.origin usage."""
        if not self.source_code:
            return

        if 'tx.origin' in self.source_code:
            self._add_finding(
                "MEDIUM",
                "tx.origin",
                "Use of tx.origin for authorization",
                "tx.origin should not be used for authorization. Use msg.sender instead.",
                "tx.origin found in source code"
            )

    def _check_selfdestruct(self):
        """Check for selfdestruct usage."""
        if not self.source_code:
            return

        if 'selfdestruct' in self.source_code or 'suicide(' in self.source_code:
            self._add_finding(
                "MEDIUM",
                "Self-destruct",
                "Contract contains selfdestruct",
                "selfdestruct can be used to destroy the contract and send remaining funds.",
            )

    def _check_delegatecall(self):
        """Check for delegatecall usage."""
        if not self.source_code:
            return

        delegatecalls = re.findall(r'delegatecall\(', self.source_code)
        if delegatecalls:
            has_user_input = bool(re.search(
                r'delegatecall\([^)]*msg\.sender|delegatecall\([^)]*calldata|delegatecall\([^)]*input',
                self.source_code
            ))
            severity = "HIGH" if has_user_input else "INFO"
            self._add_finding(
                severity,
                "Delegatecall",
                f"Found {len(delegatecalls)} delegatecall(s)",
                "delegatecall executes code in the context of the caller.",
            )

    def _check_timestamp_dependence(self):
        """Check for block.timestamp dependence."""
        if not self.source_code:
            return

        timestamp_uses = re.findall(r'block\.timestamp|now\b', self.source_code)
        if len(timestamp_uses) > 3:
            self._add_finding(
                "LOW",
                "Timestamp Dependence",
                f"High block.timestamp usage ({len(timestamp_uses)} occurrences)",
                "block.timestamp can be manipulated by miners within ~15 seconds.",
            )

    def _check_integer_overflow(self):
        """Check for integer overflow patterns (pre-0.8.0)."""
        if not self.source_code:
            return

        if self.compiler_version and re.search(r'0\.[89]\.', self.compiler_version):
            self.info["overflow_protection"] = "Built-in (Solidity >=0.8.0)"
            return

        has_safemath = bool(re.search(r'SafeMath|using\s+SafeMath', self.source_code))
        if not has_safemath:
            self._add_finding(
                "MEDIUM",
                "Integer Overflow",
                "No SafeMath library and compiler <0.8.0",
                "Solidity <0.8.0 does not have built-in overflow protection.",
            )

    def _check_flash_loan_exposure(self):
        """Check for flash loan attack vectors."""
        if not self.source_code:
            return

        has_oracle = bool(re.search(r'getAmountsOut|getAmountsIn|latestAnswer|chainlink|oracle|priceFeed', self.source_code, re.IGNORECASE))
        has_deposit = bool(re.search(r'deposit|mint|swap|addLiquidity', self.source_code, re.IGNORECASE))

        if has_oracle and has_deposit:
            self._add_finding(
                "INFO",
                "Flash Loan",
                "Protocol uses price oracles with deposit/swap functions",
                "Ensure price oracles are resistant to flash loan manipulation.",
            )

    def _check_oracle_manipulation(self):
        """Check for oracle manipulation patterns."""
        if not self.source_code:
            return

        if re.search(r'getReserves|slot0|balanceOf.*block\.number', self.source_code):
            self._add_finding(
                "INFO",
                "Oracle Manipulation",
                "Potential single-block price manipulation vector",
                "Using DEX reserves or single-block data for pricing can be manipulated.",
            )

    def _check_upgradeable(self):
        """Check for upgradeable contract patterns."""
        if not self.source_code:
            return

        has_proxy = bool(re.search(
            r'UUPS|TransparentProxy|ERC1967|upgradeTo|upgradeToAndCall|_upgradeTo',
            self.source_code
        ))

        if has_proxy:
            has_timelock = bool(re.search(r'timelock|TimelockController|delay', self.source_code, re.IGNORECASE))
            severity = "INFO" if has_timelock else "MEDIUM"
            title = "Upgradeable contract detected"
            desc = "Contract uses upgradeable proxy pattern."
            if not has_timelock:
                desc += " No timelock found for upgrade function."
            self._add_finding(severity, "Upgradeable", title, desc)

    def _check_centralization(self):
        """Check for centralization risks."""
        if not self.source_code:
            return

        single_owner = bool(re.search(r'address\s+(?:public\s+)?(?:owner|admin)\s*;', self.source_code))
        has_multisig = bool(re.search(r'MultiSig|multisig|GnosisSafe|gnosis', self.source_code, re.IGNORECASE))

        if single_owner and not has_multisig:
            self._add_finding(
                "LOW",
                "Centralization",
                "Single owner/admin without multisig",
                "Contract is controlled by a single address. Consider using a multisig.",
            )

    def _check_missing_events(self):
        """Check for state changes without events."""
        if not self.source_code:
            return

        emits = len(re.findall(r'emit\s+\w+', self.source_code))
        state_funcs = len(re.findall(r'function\s+\w+.*\{[^}]*storage', self.source_code, re.DOTALL))

        if state_funcs > 5 and emits < 2:
            self._add_finding(
                "INFO",
                "Missing Events",
                f"Low event emission ({emits} events vs {state_funcs} state-changing functions)",
                "State-changing functions should emit events for off-chain monitoring.",
            )

    def _check_gas_griefing(self):
        """Check for gas griefing patterns."""
        if not self.source_code:
            return

        unbounded = re.findall(r'for\s*\([^)]*;\s*\w+\s*<\s*(?:balances|holders|claimers|users|addresses)\.length', self.source_code)
        if unbounded:
            self._add_finding(
                "MEDIUM",
                "Gas Griefing",
                f"Found {len(unbounded)} potentially unbounded loop(s)",
                "Loops over dynamic arrays can exceed block gas limit.",
            )

    def _check_first_deposit_attack(self):
        """Check for first-depositor vault attack."""
        if not self.source_code:
            return

        has_vault = bool(re.search(r'ERC4626|withdraw|deposit.*share|totalSupply.*==.*0', self.source_code, re.IGNORECASE))
        has_inflation_check = bool(re.search(r'totalSupply.*==.*0|firstDeposit|initialDeposit|MINIMUM_AMOUNT', self.source_code))

        if has_vault and not has_inflation_check:
            self._add_finding(
                "MEDIUM",
                "First Deposit",
                "ERC-4626 vault may be vulnerable to first-depositor attack",
                "First depositor can manipulate share price by donating tokens.",
            )

    def _generate_report(self) -> dict:
        """Generate the final report."""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.findings.sort(key=lambda x: severity_order.get(x["severity"], 5))

        counts = {}
        for f in self.findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        return {
            "address": self.address_checksum,
            "contract_name": self.contract_name,
            "compiler": self.compiler_version,
            "chain_id": self.chain_id,
            "info": self.info,
            "findings": self.findings,
            "summary": {
                "total": len(self.findings),
                "critical": counts.get("CRITICAL", 0),
                "high": counts.get("HIGH", 0),
                "medium": counts.get("MEDIUM", 0),
                "low": counts.get("LOW", 0),
                "info": counts.get("INFO", 0),
            },
            "scan_time": datetime.now(timezone.utc).isoformat(),
        }

    def _error(self, message: str) -> dict:
        """Return error result."""
        return {
            "address": self.address_checksum,
            "error": message,
            "scan_time": datetime.now(timezone.utc).isoformat(),
        }
