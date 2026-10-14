AI_EXPLANATIONS = {

    "Reentrancy Risk":
    "Reentrancy vulnerabilities may allow attackers to repeatedly call vulnerable functions before internal state updates occur. This can lead to unauthorized fund draining attacks similar to the DAO exploit.",

    "tx.origin Usage":
    "Using tx.origin for authorization is insecure because malicious contracts may manipulate transaction flow and bypass authentication checks.",

    "delegatecall Usage":
    "delegatecall executes external code within the current contract storage context, potentially causing privilege escalation or malicious storage manipulation.",

    "selfdestruct Usage":
    "selfdestruct can permanently destroy smart contract bytecode and transfer remaining funds, creating severe operational and financial risks if improperly protected.",

    "Low-level call Usage":
    "Low-level calls bypass Solidity safety checks and may silently fail, increasing attack surfaces and unexpected execution behavior.",

    "Unchecked External Call":
    "Unchecked external calls may fail without reverting transactions, leading to inconsistent contract states and hidden execution failures.",

    "Timestamp Dependence":
    "Miners can manipulate block timestamps slightly, making timestamp-dependent business logic vulnerable to manipulation attacks.",

    "Weak Randomness":
    "Blockchain variables such as block.timestamp and blockhash are predictable and unsuitable for secure randomness generation.",

    "Hardcoded Address":
    "Hardcoded wallet addresses reduce contract flexibility and may introduce trust or operational security concerns.",

    "Unsafe Arithmetic":
    "Unsafe arithmetic operations may lead to integer overflow or underflow vulnerabilities in older Solidity versions.",

    "Front Running Risk":
    "Public mempool visibility may allow attackers to observe pending transactions and submit competing transactions with higher gas fees."

}

def generate_ai_recommendation(vulnerability_name):

    return AI_EXPLANATIONS.get(
        vulnerability_name,
        "Potential security issue detected. Manual security review is recommended."
    )