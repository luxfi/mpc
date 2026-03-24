# Safe + MPC Threshold Integration

## Problem

DAO governance requires two properties that are in tension:

1. **Operational availability** -- Lux must be able to execute bridge/operational
   transactions without customer involvement (e.g., rebalancing, emergency).
2. **Customer co-approval** -- For governance actions (treasury, parameter changes),
   the customer must actively participate. Lux alone should not be able to execute.

A 3-of-5 MPC where Lux holds 3 nodes gives Lux signing majority. This solves (1)
but violates (2). Adding Safe (Gnosis Safe) on-chain multisig solves both.

## Architecture

```
                          On-Chain (EVM)
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                  Safe Multisig                       │    │
│  │         2-of-3 owners (on-chain threshold)           │    │
│  │                                                      │    │
│  │  Owner A: SafeFROSTSigner (Lux ops key)              │    │
│  │  Owner B: SafeFROSTSigner (DAO governance key)       │    │
│  │  Owner C: SafeFROSTSigner (Emergency recovery key)   │    │
│  └──────────┬──────────────┬──────────────┬─────────────┘    │
│             │              │              │                   │
│  ┌──────────▼──┐  ┌────────▼──────┐  ┌───▼──────────────┐   │
│  │ FROST.sol   │  │  FROST.sol    │  │   FROST.sol      │   │
│  │ verify()    │  │  verify()     │  │   verify()       │   │
│  └──────┬──────┘  └───────┬───────┘  └────────┬──────────┘   │
│         │                 │                    │              │
└─────────┼─────────────────┼────────────────────┼──────────────┘
          │                 │                    │
          │   Off-Chain (MPC Threshold)          │
┌─────────▼─────────────────▼────────────────────▼──────────────┐
│                                                               │
│  Each "owner" key is actually a 3-of-5 FROST threshold key:  │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  3-of-5 MPC Cluster                                     │  │
│  │  [lux-0] [lux-1] [lux-2] [cust-0] [cust-1]            │  │
│  │                                                         │  │
│  │  Each node holds a key share for EACH Safe owner key.   │  │
│  │  DKG runs once per owner key. Different key IDs.        │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

## Effective Security

- **Safe threshold**: 2-of-3 on-chain
- **MPC threshold**: 3-of-5 off-chain per owner key
- **Effective**: To execute a governance transaction, an attacker needs:
  - 2 Safe owner signatures (on-chain)
  - For each signature: 3 MPC shares (off-chain)
  - Worst case: 6 shares across 2 different key sets

This is not a simple 6-of-15. The structure is hierarchical: the attacker must
compromise the right combination of shares for 2 different keys.

## Key Generation

Three separate DKG ceremonies, one per Safe owner:

```bash
# Owner A: Lux operational key
curl -X POST http://mpc-lux-api:9800/keygen \
  -d '{"keyId":"safe-owner-ops","threshold":3,"parties":5,"curve":"secp256k1","protocol":"frost"}'

# Owner B: DAO governance key (requires customer participation)
curl -X POST http://mpc-lux-api:9800/keygen \
  -d '{"keyId":"safe-owner-dao","threshold":3,"parties":5,"curve":"secp256k1","protocol":"frost"}'

# Owner C: Emergency recovery key
curl -X POST http://mpc-lux-api:9800/keygen \
  -d '{"keyId":"safe-owner-recovery","threshold":3,"parties":5,"curve":"secp256k1","protocol":"frost"}'
```

Each DKG produces a FROST group public key (secp256k1 point). This public key
is used to deploy a SafeFROSTSigner contract on-chain.

## Contract Deployment

### Step 1: Deploy FROST Signers

For each MPC-generated public key, deploy a SafeFROSTSigner:

```solidity
// px, py are the secp256k1 public key coordinates from DKG
SafeFROSTSigner signerOps = new SafeFROSTSigner(px_ops, py_ops);
SafeFROSTSigner signerDAO = new SafeFROSTSigner(px_dao, py_dao);
SafeFROSTSigner signerRecovery = new SafeFROSTSigner(px_recovery, py_recovery);
```

### Step 2: Deploy Safe with FROST Signers as Owners

```solidity
address[] memory owners = new address[](3);
owners[0] = address(signerOps);
owners[1] = address(signerDAO);
owners[2] = address(signerRecovery);

// 2-of-3 Safe: any 2 FROST signers can approve
safe.setup(owners, 2, address(0), "", address(0), address(0), 0, payable(0));
```

### Step 3 (Optional): Deploy Co-Signer Guard

For transactions that MUST have customer co-approval regardless of Safe threshold:

```solidity
// SafeFROSTCoSigner as a transaction guard
SafeFROSTCoSigner guard = new SafeFROSTCoSigner(px_dao, py_dao);
safe.setGuard(address(guard));
```

The guard checks that the DAO governance key co-signed every transaction.
This means even if Lux signs with Owner A and Owner C (both operational keys),
the guard requires a FROST signature from the DAO key. Customer participation
is enforced at the smart contract level.

## Signing Flow

### Normal DAO Governance Transaction

```
1. Customer proposes transaction via Safe UI/API
2. Safe computes safeTxHash = keccak256(to, value, data, ...)
3. MPC threshold sign with Owner B (DAO key):
   - Customer's 2 nodes + 1 Lux node participate
   - Produces FROST signature (rx, ry, z)
4. SafeFROSTSigner(DAO).isValidSignature(safeTxHash, sig) returns magic bytes
5. Lux signs with Owner A (ops key):
   - 3 Lux nodes participate (no customer needed)
   - Produces FROST signature
6. SafeFROSTSigner(Ops).isValidSignature(safeTxHash, sig) returns magic bytes
7. Safe has 2-of-3 signatures, executes transaction
```

### Operational/Bridge Transaction (No Customer)

```
1. Lux proposes transaction
2. MPC threshold sign with Owner A (ops key):
   - 3 Lux nodes (customer not needed for threshold=3)
3. MPC threshold sign with Owner C (recovery key):
   - 3 Lux nodes
4. Safe has 2-of-3 (A + C), executes
5. If guard is set: guard requires DAO key co-sign
   - If guard IS set: Lux cannot execute without customer
   - If guard is NOT set: Lux can execute with ops + recovery
```

### Guard vs No Guard

| Scenario | No Guard | With CoSigner Guard |
|----------|----------|---------------------|
| Lux alone (ops + recovery) | CAN execute | BLOCKED |
| Lux + Customer (ops + dao) | CAN execute | CAN execute |
| Customer alone | BLOCKED (2 MPC nodes < threshold) | BLOCKED |

Use the guard for DAO treasuries where customer must always co-approve.
Omit the guard for bridge/operational wallets where Lux needs autonomy.

## FROST Signature Format

The FROST.sol library verifies FROST(secp256k1, SHA-256) Schnorr signatures
per RFC 9591. The signature is encoded as `abi.encode(rx, ry, z)`:

- `rx` (uint256): x-coordinate of the group commitment point R
- `ry` (uint256): y-coordinate of the group commitment point R
- `z`  (uint256): signature scalar

The SafeFROSTSigner computes `address(keccak256(px, py))` as the signer
identity. The FROST.verify function uses the ecrecover precompile trick
to verify `-z*G + e*P = R` without explicit point arithmetic.

Constraint: the group public key's x-coordinate must be less than the
secp256k1 curve order (N). The safe-frost `split` command retries key
generation until this property holds. The MPC DKG does the same.

## Contracts Reference

All contracts are in `github.com/luxfi/safe-frost/contracts/`:

| Contract | Purpose |
|----------|---------|
| `FROST.sol` | Library: FROST(secp256k1, SHA-256) Schnorr verification |
| `SafeFROSTSigner.sol` | ERC-1271 signature validator, Safe owner |
| `SafeFROSTCoSigner.sol` | Transaction guard, enforces co-signing |
| `FROSTAccount.sol` | ERC-4337 account abstraction (standalone) |

## Deployment Addresses

Deploy FROST.sol as a library, then link SafeFROSTSigner and SafeFROSTCoSigner.
Use the standard Safe proxy factory for the Safe itself.

Target chains for deployment:
- Lux C-Chain (chain ID 96369)
- Lux subnet chains (Zoo, Hanzo, SPC, Pars)
- Ethereum mainnet (for cross-chain governance)
