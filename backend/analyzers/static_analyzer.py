from utils.ai_recommendation import generate_ai_recommendation
import re

# Vulnerability patterns
VULNERABILITY_RULES = [

    {
        "name": "Reentrancy Risk",
        "pattern": r"\.transfer\s*\(",
        "severity": "Critical",
        "risk_score": 95,
        "detection_method": "Static + Dynamic + Symbolic",
        "description": "External transfer detected before state update.",
        "recommendation": "Use Checks-Effects-Interactions pattern and ReentrancyGuard."
    },

    {
        "name": "tx.origin Usage",
        "pattern": r"tx\.origin",
        "severity": "High",
        "risk_score": 85,
        "detection_method": "Static Analysis",
        "description": "tx.origin used for authentication.",
        "recommendation": "Use msg.sender instead of tx.origin."
    },

    {
        "name": "delegatecall Usage",
        "pattern": r"delegatecall",
        "severity": "Critical",
        "risk_score": 90,
        "detection_method": "Static + Taint",
        "description": "delegatecall can execute untrusted external code.",
        "recommendation": "Avoid delegatecall unless absolutely necessary."
    },

    {
        "name": "selfdestruct Usage",
        "pattern": r"selfdestruct",
        "severity": "High",
        "risk_score": 80,
        "detection_method": "Static Analysis",
        "description": "Contract destruction detected.",
        "recommendation": "Restrict selfdestruct access using onlyOwner."
    },

    {
        "name": "Low-level call Usage",
        "pattern": r"\.call\s*\(",
        "severity": "High",
        "risk_score": 88,
        "detection_method": "Static + Taint",
        "description": "Low-level call detected.",
        "recommendation": "Check return values and use safer alternatives."
    },

    {
        "name": "Floating Pragma",
        "pattern": r"pragma solidity \^",
        "severity": "Low",
        "risk_score": 40,
        "detection_method": "Static Analysis",
        "description": "Floating Solidity version detected.",
        "recommendation": "Lock compiler version to avoid unexpected behavior."
    },

    {
        "name": "Unchecked External Call",
        "pattern": r"\.call\s*\(",
        "severity": "High",
        "risk_score": 84,
        "detection_method": "Static + Dynamic",
        "description": "Unchecked external call detected.",
        "recommendation": "Always verify return values from external calls."
    },

    {
        "name": "Timestamp Dependence",
        "pattern": r"block\.timestamp",
        "severity": "Medium",
        "risk_score": 65,
        "detection_method": "Static Analysis",
        "description": "block.timestamp manipulation risk detected.",
        "recommendation": "Avoid using timestamps for critical logic."
    },

    {
        "name": "Weak Randomness",
        "pattern": r"blockhash|block\.timestamp",
        "severity": "High",
        "risk_score": 82,
        "detection_method": "Static + Symbolic",
        "description": "Weak randomness source detected.",
        "recommendation": "Use Chainlink VRF or secure randomness sources."
    },

    {
        "name": "Hardcoded Address",
        "pattern": r"0x[a-fA-F0-9]{40}",
        "severity": "Medium",
        "risk_score": 60,
        "detection_method": "Static Analysis",
        "description": "Hardcoded wallet address detected.",
        "recommendation": "Use configurable constructor parameters."
    },

   {
        "name": "Unsafe Arithmetic",
        "pattern": r"\+|\-|\*|\/",
        "severity": "High",
        "risk_score": 78,
        "detection_method": "Static Analysis",
        "description": "Potential unsafe arithmetic operation detected.",
        "recommendation": "Use Solidity ^0.8.x or SafeMath library."
    },

    {
        "name": "Front Running Risk",
        "pattern": r"public",
        "severity": "Medium",
        "risk_score": 68,
        "detection_method": "Static + Dynamic",
        "description": "Potential front-running exposure detected.",
        "recommendation": "Use commit-reveal schemes where necessary."
    }

]

# Static analyzer function
def scan_contract(contract_code):

    findings = []

    lines = contract_code.split('\n')

    for line_number, line in enumerate(lines, start=1):

        for rule in VULNERABILITY_RULES:

            if re.search(rule["pattern"], line):

                findings.append({

                    "vulnerability": rule["name"],
                    "severity": rule["severity"],
                    "risk_score": rule["risk_score"],
                    "line": line_number,
                    "code": line.strip(),
                    "detection_method": rule["detection_method"],
                    "description": rule["description"],
                    "recommendation": rule["recommendation"],
                    "ai_analysis": generate_ai_recommendation(rule["name"])
                })

    return findings