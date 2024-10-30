# Bitcoin Privacy Layer

A privacy-preserving smart contract implementation for Bitcoin transactions using zero-knowledge proofs and Merkle trees. This contract enables confidential transactions while maintaining the security and verifiability of the Bitcoin network.

## Overview

This smart contract implements a privacy layer that allows users to make anonymous transactions using a commitment-nullifier scheme backed by zero-knowledge proofs. It follows the SIP-010 fungible token standard and implements a Merkle tree-based verification system.

## Features

- **Zero-Knowledge Privacy**: Enables private transactions using commitment-nullifier pairs
- **Merkle Tree Verification**: Implements a 20-level Merkle tree for efficient proof verification
- **SIP-010 Compatibility**: Works with any token implementing the SIP-010 fungible token standard
- **Double-Spend Prevention**: Uses nullifier tracking to prevent double-spending
- **Deposit/Withdrawal System**: Secure system for depositing and withdrawing funds

## Technical Specifications

- Merkle Tree Height: 20 levels
- Maximum Deposits: 2^20 (1,048,576) unique deposits
- Proof Size: 20 elements per proof
- Hash Function: SHA-256

## Core Functions

### Deposit

```clarity
(deposit (commitment (buff 32)) (amount uint) (token <ft-trait>))
```

Allows users to deposit tokens into the privacy pool:

- Creates a commitment
- Updates the Merkle tree
- Transfers tokens to the contract
- Returns the leaf index of the deposit

### Withdraw

```clarity
(withdraw (nullifier (buff 32)) (root (buff 32)) (proof (list 20 (buff 32)))
         (recipient principal) (token <ft-trait>) (amount uint))
```

Enables private withdrawals from the pool:

- Verifies the zero-knowledge proof
- Checks nullifier uniqueness
- Transfers tokens to the recipient
- Marks the nullifier as used

## Error Codes

| Code | Description              |
| ---- | ------------------------ |
| 1001 | Not authorized           |
| 1002 | Invalid amount           |
| 1003 | Insufficient balance     |
| 1004 | Invalid commitment       |
| 1005 | Nullifier already exists |
| 1006 | Invalid proof            |
| 1007 | Tree full                |

## Read-Only Functions

- `get-current-root`: Returns the current Merkle tree root
- `is-nullifier-used`: Checks if a nullifier has been previously used
- `get-deposit-info`: Retrieves information about a specific deposit

## Security Considerations

1. **Zero-Value Checks**: The contract enforces non-zero commitments and amounts
2. **Tree Capacity**: Implements checks to prevent overflow of the Merkle tree
3. **Nullifier Tracking**: Maintains a registry of used nullifiers to prevent double-spending
4. **Proof Verification**: Requires valid zero-knowledge proofs for withdrawals

## Dependencies

- SIP-010 Fungible Token Trait
- SHA-256 hash function support
- Contract-call functionality

## Usage Example

1. **Making a Deposit**:

```clarity
(contract-call? .privacy-layer deposit
    0x1234...  ;; commitment
    u100       ;; amount
    .token-contract)  ;; SIP-010 token contract
```

2. **Performing a Withdrawal**:

```clarity
(contract-call? .privacy-layer withdraw
    0x5678...  ;; nullifier
    0xabcd...  ;; current root
    (list ...)  ;; merkle proof
    tx-sender   ;; recipient
    .token-contract  ;; token contract
    u100)      ;; amount
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

**Note**: This implementation assumes the availability of a zero-knowledge proof system and proper integration with the Bitcoin network. Additional documentation regarding the proof system and network integration will be provided separately.
