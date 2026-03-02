package db

import (
	"time"

	"github.com/hanzoai/orm"
)

// Organization represents a tenant organization.
type Organization struct {
	orm.Model[Organization]
	Name string `json:"name"`
	Slug string `json:"slug"`
}

func init() { orm.Register[Organization]("organization") }

// User represents an authenticated user within an organization.
type User struct {
	orm.Model[User]
	OrgID        string  `json:"orgId"`
	Email        string  `json:"email"`
	PasswordHash string  `json:"passwordHash"` // never returned directly; use safeUser() in handlers
	Role         string  `json:"role"`
	MFASecret    *string `json:"mfaSecret,omitempty"` // never returned directly
}

func init() { orm.Register[User]("user") }

// APIKey represents an API key for programmatic access.
type APIKey struct {
	orm.Model[APIKey]
	OrgID       string     `json:"orgId"`
	Name        string     `json:"name"`
	KeyHash     string     `json:"keyHash"`
	KeyPrefix   string     `json:"keyPrefix"`
	Permissions []string   `json:"permissions"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
	LastUsedAt  *time.Time `json:"lastUsedAt,omitempty"`
}

func init() { orm.Register[APIKey]("api-key") }

// Vault is a logical grouping of wallets.
type Vault struct {
	orm.Model[Vault]
	OrgID       string  `json:"orgId"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	AppID       *string `json:"appId,omitempty"`
}

func init() { orm.Register[Vault]("vault") }

// Wallet holds an MPC key share group.
type Wallet struct {
	orm.Model[Wallet]
	VaultID      string   `json:"vaultId"`
	OrgID        string   `json:"orgId"`
	WalletID     string   `json:"walletId"`
	Name         *string  `json:"name,omitempty"`
	KeyType      string   `json:"keyType"`
	Protocol     string   `json:"protocol,omitempty"` // cggmp21, frost, lss
	ECDSAPubkey  *string  `json:"ecdsaPubkey,omitempty"`
	EDDSAPubkey  *string  `json:"eddsaPubkey,omitempty"`
	EthAddress   *string  `json:"ethAddress,omitempty"`
	BtcAddress   *string  `json:"btcAddress,omitempty"`
	SolAddress   *string  `json:"solAddress,omitempty"`
	Threshold    int      `json:"threshold"`
	Participants []string `json:"participants"`
	Version      int      `json:"version"`
	Status       string   `json:"status"`
	CreatedBy    *string  `json:"createdBy,omitempty"`
}

func init() { orm.Register[Wallet]("wallet") }

// Transaction is a blockchain transaction record with full lifecycle tracking.
//
// Status flow:
//
//	pending_approval → approved → signing → signed → broadcast → confirming → finalized
//	                                                                        → failed
//	                                                                        → reverted
type Transaction struct {
	orm.Model[Transaction]
	OrgID           string     `json:"orgId"`
	WalletID        *string    `json:"walletId,omitempty"`
	TxType          string     `json:"txType"`
	Chain           string     `json:"chain"`
	ToAddress       *string    `json:"toAddress,omitempty"`
	Amount          *string    `json:"amount,omitempty"`
	Token           *string    `json:"token,omitempty"`
	TxHash          *string    `json:"txHash,omitempty"`
	RawTx           []byte     `json:"rawTx,omitempty"`
	SignatureR      *string    `json:"signatureR,omitempty"`
	SignatureS      *string    `json:"signatureS,omitempty"`
	SignatureEdDSA  *string    `json:"signatureEdDSA,omitempty"`
	Status          string     `json:"status"`
	InitiatedBy     *string    `json:"initiatedBy,omitempty"`
	ApprovedBy      []string   `json:"approvedBy,omitempty"`
	RejectedBy      *string    `json:"rejectedBy,omitempty"`
	RejectionReason *string    `json:"rejectionReason,omitempty"`
	SignedAt        *time.Time `json:"signedAt,omitempty"`
	BroadcastAt     *time.Time `json:"broadcastAt,omitempty"`

	// On-chain receipt tracking — answers "did the tx land?"
	BroadcastHash *string `json:"broadcastHash,omitempty"` // actual hash returned from network
	Nonce         *int64  `json:"nonce,omitempty"`          // nonce used on-chain
	BlockNumber   *int64  `json:"blockNumber,omitempty"`    // block the tx was included in
	BlockHash     *string `json:"blockHash,omitempty"`      // hash of the containing block
	ReceiptStatus *int    `json:"receiptStatus,omitempty"`  // 0=reverted, 1=success
	GasUsed       *string `json:"gasUsed,omitempty"`
	RevertReason  *string `json:"revertReason,omitempty"` // decoded revert reason if receiptStatus=0

	// Finality tracking — answers "when did we record it as confirmed?"
	Confirmations     int        `json:"confirmations"`               // current confirmation count
	TargetConfirms    int        `json:"targetConfirmations"`         // required confirmations (default 12)
	FinalizedAt       *time.Time `json:"finalizedAt,omitempty"`       // when tx reached target confirmations
	FinalizationBlock *int64     `json:"finalizationBlock,omitempty"` // block at which finality was declared

	// State machine history: every transition recorded with timestamp
	StatusHistory []StatusTransition `json:"statusHistory,omitempty"`

	// Settlement (cross-chain / matched trade)
	IntentID         *string    `json:"intentId,omitempty"`         // linked intent record
	SettlementTxHash *string    `json:"settlementTxHash,omitempty"` // settlement tx on destination chain
	SettledAt        *time.Time `json:"settledAt,omitempty"`
}

// StatusTransition records a single state change with its timestamp and context.
type StatusTransition struct {
	From      string     `json:"from"`
	To        string     `json:"to"`
	Timestamp time.Time  `json:"timestamp"`
	Detail    string     `json:"detail,omitempty"`
	BlockNum  *int64     `json:"blockNumber,omitempty"`
	TxHash    *string    `json:"txHash,omitempty"`
	Actor     *string    `json:"actor,omitempty"` // userID or "system"
}

// RecordTransition appends a status transition and updates the current status.
func (tx *Transaction) RecordTransition(to, detail string, actor *string) {
	now := time.Now()
	tx.StatusHistory = append(tx.StatusHistory, StatusTransition{
		From:      tx.Status,
		To:        to,
		Timestamp: now,
		Detail:    detail,
		Actor:     actor,
	})
	tx.Status = to
}

func init() { orm.Register[Transaction]("transaction") }

// Policy is a signing policy rule.
type Policy struct {
	orm.Model[Policy]
	OrgID             string   `json:"orgId"`
	VaultID           *string  `json:"vaultId,omitempty"`
	Name              string   `json:"name"`
	Priority          int      `json:"priority"`
	Action            string   `json:"action"`
	Conditions        []byte   `json:"conditions"`
	RequiredApprovers int      `json:"requiredApprovers"`
	ApproverRoles     []string `json:"approverRoles"`
	Enabled           bool     `json:"enabled"`
}

func init() { orm.Register[Policy]("policy") }

// AddressWhitelist is an approved destination address.
type AddressWhitelist struct {
	orm.Model[AddressWhitelist]
	OrgID     string  `json:"orgId"`
	VaultID   *string `json:"vaultId,omitempty"`
	Address   string  `json:"address"`
	Chain     string  `json:"chain"`
	Label     *string `json:"label,omitempty"`
	CreatedBy *string `json:"createdBy,omitempty"`
}

func init() { orm.Register[AddressWhitelist]("address-whitelist") }

// AuditEntry is an immutable audit log record.
type AuditEntry struct {
	orm.Model[AuditEntry]
	OrgID        string  `json:"orgId"`
	UserID       *string `json:"userId,omitempty"`
	Action       string  `json:"action"`
	ResourceType *string `json:"resourceType,omitempty"`
	ResourceID   *string `json:"resourceId,omitempty"`
	Details      []byte  `json:"details,omitempty"`
	IPAddress    *string `json:"ipAddress,omitempty"`
}

func init() { orm.Register[AuditEntry]("audit-entry") }

// Webhook is an outbound event delivery endpoint.
type Webhook struct {
	orm.Model[Webhook]
	OrgID   string   `json:"orgId"`
	URL     string   `json:"url"`
	Secret  string   `json:"secret"`
	Events  []string `json:"events"`
	Enabled bool     `json:"enabled"`
}

func init() { orm.Register[Webhook]("webhook") }

// Subscription is a recurring payment schedule.
type Subscription struct {
	orm.Model[Subscription]
	OrgID            string     `json:"orgId"`
	WalletID         *string    `json:"walletId,omitempty"`
	Name             string     `json:"name"`
	ProviderName     *string    `json:"providerName,omitempty"`
	RecipientAddress string     `json:"recipientAddress"`
	Chain            string     `json:"chain"`
	Token            *string    `json:"token,omitempty"`
	Amount           string     `json:"amount"`
	Currency         string     `json:"currency"`
	Interval         string     `json:"interval"`
	NextPaymentAt    time.Time  `json:"nextPaymentAt"`
	LastPaymentAt    *time.Time `json:"lastPaymentAt,omitempty"`
	LastTxID         *string    `json:"lastTxId,omitempty"`
	Status           string     `json:"status"`
	MaxRetries       int        `json:"maxRetries"`
	RetryCount       int        `json:"retryCount"`
	RequireBalance   bool       `json:"requireBalance"`
	CreatedBy        *string    `json:"createdBy,omitempty"`
	CancelledBy      *string    `json:"cancelledBy,omitempty"`
	CancelledAt      *time.Time `json:"cancelledAt,omitempty"`
}

func init() { orm.Register[Subscription]("subscription") }

// PaymentRequest is a one-time payment link.
type PaymentRequest struct {
	orm.Model[PaymentRequest]
	OrgID            string     `json:"orgId"`
	WalletID         *string    `json:"walletId,omitempty"`
	RequestToken     string     `json:"requestToken"`
	MerchantName     *string    `json:"merchantName,omitempty"`
	RecipientAddress string     `json:"recipientAddress"`
	Chain            string     `json:"chain"`
	Token            *string    `json:"token,omitempty"`
	Amount           string     `json:"amount"`
	Memo             *string    `json:"memo,omitempty"`
	Status           string     `json:"status"`
	ExpiresAt        *time.Time `json:"expiresAt,omitempty"`
	PaidTxID         *string    `json:"paidTxId,omitempty"`
}

func init() { orm.Register[PaymentRequest]("payment-request") }

// WebAuthnCredential stores a FIDO2/WebAuthn credential for biometric signing.
type WebAuthnCredential struct {
	orm.Model[WebAuthnCredential]
	OrgID      string  `json:"orgId"`
	UserID     string  `json:"userId"`
	WebAuthnID string  `json:"webAuthnId,omitempty"`
	PublicKey  string  `json:"publicKey,omitempty"`
	Challenge  string  `json:"challenge,omitempty"`
	DeviceName *string `json:"deviceName,omitempty"`
	Status     string  `json:"status"` // pending_registration, active, revoked
}

func init() { orm.Register[WebAuthnCredential]("webauthn-credential") }

// BridgeConfig stores org-scoped bridge configuration.
type BridgeConfig struct {
	orm.Model[BridgeConfig]
	OrgID              string `json:"orgId"`
	SigningWalletID    string `json:"signingWalletId,omitempty"`
	FeeCollector       string `json:"feeCollector,omitempty"`
	FeeRateBps         int    `json:"feeRateBps"`          // basis points, e.g., 100 = 1%
	MinFeeBps          int    `json:"minFeeBps,omitempty"`  // minimum fee in basis points
	MaxFeeBps          int    `json:"maxFeeBps,omitempty"`  // maximum fee in basis points
	DepositsEnabled    bool   `json:"depositsEnabled"`
	WithdrawalsEnabled bool   `json:"withdrawalsEnabled"`
}

func init() { orm.Register[BridgeConfig]("bridge-config") }

// SmartWallet is an on-chain smart contract wallet (Safe/ERC-4337).
type SmartWallet struct {
	orm.Model[SmartWallet]
	WalletID          string     `json:"walletId"`
	OrgID             string     `json:"orgId"`
	Chain             string     `json:"chain"`
	ContractAddress   string     `json:"contractAddress"`
	WalletType        string     `json:"walletType"`
	FactoryAddress    *string    `json:"factoryAddress,omitempty"`
	EntrypointAddress *string    `json:"entrypointAddress,omitempty"`
	Salt              *string    `json:"salt,omitempty"`
	Owners            []string   `json:"owners"`
	Threshold         int        `json:"threshold"`
	Status            string     `json:"status"`
	DeployedAt        *time.Time `json:"deployedAt,omitempty"`
}

func init() { orm.Register[SmartWallet]("smart-wallet") }

// Intent represents a user's signed intention to execute a trade or transfer.
// Intents are the first step of the settlement flow: the user signs what they
// want to do, then the platform co-signs, then the intent is recorded on-chain.
//
// Status flow:
//
//	pending_sign → signed → co_signed → recorded → matched → settling → settled → verified
type Intent struct {
	orm.Model[Intent]
	OrgID          string     `json:"orgId"`
	WalletID       string     `json:"walletId"`
	IntentType     string     `json:"intentType"` // buy, sell, transfer, bridge
	Chain          string     `json:"chain"`
	ToAddress      *string    `json:"toAddress,omitempty"`
	Amount         string     `json:"amount"`
	Token          *string    `json:"token,omitempty"`
	IntentHash     string     `json:"intentHash"`               // keccak256 of canonical intent data
	Signature      *string    `json:"signature,omitempty"`       // user's MPC signature (first signer)
	CoSignature    *string    `json:"coSignature,omitempty"`     // platform HSM signature (second signer)
	CoSignerKeyID  *string    `json:"coSignerKeyId,omitempty"`   // HSM key ID used for co-signing
	OnChainTxHash  *string    `json:"onChainTxHash,omitempty"`   // tx that recorded intent on-chain
	RecordedAt     *time.Time `json:"recordedAt,omitempty"`      // when on-chain recording confirmed
	RecordedBlock  *int64     `json:"recordedBlock,omitempty"`   // block number of on-chain record
	MatchID        *string    `json:"matchId,omitempty"`         // from order matching engine
	MatchedAt      *time.Time `json:"matchedAt,omitempty"`
	Status         string     `json:"status"`
	ExpiresAt      *time.Time `json:"expiresAt,omitempty"`
	StatusHistory  []StatusTransition `json:"statusHistory,omitempty"`
}

func init() { orm.Register[Intent]("intent") }

// Settlement tracks the lifecycle from matched trade to finalized on-chain settlement.
// It links an intent to its settlement transaction and records HSM multisig attestations.
type Settlement struct {
	orm.Model[Settlement]
	OrgID                string          `json:"orgId"`
	IntentID             string          `json:"intentId"`
	MatchID              *string         `json:"matchId,omitempty"`
	SettlementTxHash     *string         `json:"settlementTxHash,omitempty"`
	FinalizeTxHash       *string         `json:"finalizeTxHash,omitempty"`
	FinalizedBlockNumber *int64          `json:"finalizedBlockNumber,omitempty"`
	HSMSignatures        []HSMSignature  `json:"hsmSignatures,omitempty"`
	// Transfer agency verification
	TransferAgencyHash       *string    `json:"transferAgencyHash,omitempty"`
	TransferAgencyVerified   bool       `json:"transferAgencyVerified"`
	TransferAgencyVerifiedAt *time.Time `json:"transferAgencyVerifiedAt,omitempty"`
	// Timestamps
	MatchedAt    *time.Time `json:"matchedAt,omitempty"`
	SignedAt     *time.Time `json:"signedAt,omitempty"`
	BroadcastAt  *time.Time `json:"broadcastAt,omitempty"`
	FinalizedAt  *time.Time `json:"finalizedAt,omitempty"`
	VerifiedAt   *time.Time `json:"verifiedAt,omitempty"`
	Status       string     `json:"status"` // pending, hsm_signing, broadcast, confirming, finalized, verified, failed
	StatusHistory []StatusTransition `json:"statusHistory,omitempty"`
}

// HSMSignature is an attestation from a liquidity multisig signer backed by HSM.
type HSMSignature struct {
	SignerID  string    `json:"signerId"`
	KeyID     string    `json:"keyId"`
	Signature string    `json:"signature"` // hex-encoded
	Provider  string    `json:"provider"`  // aws, gcp, azure, zymbit, kms
	SignedAt  time.Time `json:"signedAt"`
}

func init() { orm.Register[Settlement]("settlement") }

// WalletBackup records a wallet key share backup with Shamir-sharded encryption key.
// The backup key is split into shards stored across different destinations
// (e.g., iCloud Keychain + Platform HSM) so that no single party can decrypt alone.
type WalletBackup struct {
	orm.Model[WalletBackup]
	OrgID              string    `json:"orgId"`
	WalletID           string    `json:"walletId"`
	BackupID           string    `json:"backupId"` // unique backup identifier
	Threshold          int       `json:"threshold"` // T shards required to reconstruct
	TotalShards        int       `json:"totalShards"`
	EncryptedKeyShare  []byte    `json:"encryptedKeyShare,omitempty"` // AES-256-GCM encrypted wallet key share
	Shards             []BackupShard `json:"shards,omitempty"`
	Status             string    `json:"status"` // active, recovered, revoked
}

// BackupShard is a labeled Shamir share with its storage destination.
type BackupShard struct {
	Index       int       `json:"index"`
	Destination string    `json:"destination"` // icloud, hsm, offline, custody
	StorageRef  *string   `json:"storageRef,omitempty"` // reference ID in destination system
	CreatedAt   time.Time `json:"createdAt"`
	VerifiedAt  *time.Time `json:"verifiedAt,omitempty"`
}

func init() { orm.Register[WalletBackup]("wallet-backup") }
