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
	PasswordHash string  `json:"passwordHash"`
	Role         string  `json:"role"`
	MFASecret    *string `json:"mfaSecret,omitempty"`
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

// Transaction is a blockchain transaction record.
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
}

func init() { orm.Register[Transaction]("transaction") }

// Policy is a signing policy rule.
type Policy struct {
	orm.Model[Policy]
	OrgID             string  `json:"orgId"`
	VaultID           *string `json:"vaultId,omitempty"`
	Name              string  `json:"name"`
	Priority          int     `json:"priority"`
	Action            string  `json:"action"`
	Conditions        []byte  `json:"conditions"`
	RequiredApprovers int     `json:"requiredApprovers"`
	ApproverRoles     []string `json:"approverRoles"`
	Enabled           bool    `json:"enabled"`
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
