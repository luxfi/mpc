package db

import (
	"time"
)

type Organization struct {
	ID        string    `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	Slug      string    `json:"slug" db:"slug"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type User struct {
	ID           string    `json:"id" db:"id"`
	OrgID        string    `json:"org_id" db:"org_id"`
	Email        string    `json:"email" db:"email"`
	PasswordHash string    `json:"-" db:"password_hash"`
	Role         string    `json:"role" db:"role"`
	MFASecret    *string   `json:"-" db:"mfa_secret"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

type APIKey struct {
	ID          string    `json:"id" db:"id"`
	OrgID       string    `json:"org_id" db:"org_id"`
	Name        string    `json:"name" db:"name"`
	KeyHash     string    `json:"-" db:"key_hash"`
	KeyPrefix   string    `json:"key_prefix" db:"key_prefix"`
	Permissions []string  `json:"permissions" db:"permissions"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
}

type Vault struct {
	ID          string    `json:"id" db:"id"`
	OrgID       string    `json:"org_id" db:"org_id"`
	Name        string    `json:"name" db:"name"`
	Description *string   `json:"description,omitempty" db:"description"`
	AppID       *string   `json:"app_id,omitempty" db:"app_id"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

type Wallet struct {
	ID           string    `json:"id" db:"id"`
	VaultID      string    `json:"vault_id" db:"vault_id"`
	OrgID        string    `json:"org_id" db:"org_id"`
	WalletID     string    `json:"wallet_id" db:"wallet_id"`
	Name         *string   `json:"name,omitempty" db:"name"`
	KeyType      string    `json:"key_type" db:"key_type"`
	ECDSAPubkey  *string   `json:"ecdsa_pubkey,omitempty" db:"ecdsa_pubkey"`
	EDDSAPubkey  *string   `json:"eddsa_pubkey,omitempty" db:"eddsa_pubkey"`
	EthAddress   *string   `json:"eth_address,omitempty" db:"eth_address"`
	BtcAddress   *string   `json:"btc_address,omitempty" db:"btc_address"`
	SolAddress   *string   `json:"sol_address,omitempty" db:"sol_address"`
	Threshold    int       `json:"threshold" db:"threshold"`
	Participants []string  `json:"participants" db:"participants"`
	Version      int       `json:"version" db:"version"`
	Status       string    `json:"status" db:"status"`
	CreatedBy    *string   `json:"created_by,omitempty" db:"created_by"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

type Transaction struct {
	ID              string     `json:"id" db:"id"`
	OrgID           string     `json:"org_id" db:"org_id"`
	WalletID        *string    `json:"wallet_id,omitempty" db:"wallet_id"`
	TxType          string     `json:"tx_type" db:"tx_type"`
	Chain           string     `json:"chain" db:"chain"`
	ToAddress       *string    `json:"to_address,omitempty" db:"to_address"`
	Amount          *string    `json:"amount,omitempty" db:"amount"`
	Token           *string    `json:"token,omitempty" db:"token"`
	TxHash          *string    `json:"tx_hash,omitempty" db:"tx_hash"`
	RawTx           []byte     `json:"-" db:"raw_tx"`
	SignatureR      *string    `json:"signature_r,omitempty" db:"signature_r"`
	SignatureS      *string    `json:"signature_s,omitempty" db:"signature_s"`
	SignatureEdDSA  *string    `json:"signature_eddsa,omitempty" db:"signature_eddsa"`
	Status          string     `json:"status" db:"status"`
	InitiatedBy     *string    `json:"initiated_by,omitempty" db:"initiated_by"`
	ApprovedBy      []string   `json:"approved_by,omitempty" db:"approved_by"`
	RejectedBy      *string    `json:"rejected_by,omitempty" db:"rejected_by"`
	RejectionReason *string    `json:"rejection_reason,omitempty" db:"rejection_reason"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	SignedAt        *time.Time `json:"signed_at,omitempty" db:"signed_at"`
	BroadcastAt     *time.Time `json:"broadcast_at,omitempty" db:"broadcast_at"`
}

type Policy struct {
	ID                string    `json:"id" db:"id"`
	OrgID             string    `json:"org_id" db:"org_id"`
	VaultID           *string   `json:"vault_id,omitempty" db:"vault_id"`
	Name              string    `json:"name" db:"name"`
	Priority          int       `json:"priority" db:"priority"`
	Action            string    `json:"action" db:"action"`
	Conditions        []byte    `json:"conditions" db:"conditions"`
	RequiredApprovers int       `json:"required_approvers" db:"required_approvers"`
	ApproverRoles     []string  `json:"approver_roles" db:"approver_roles"`
	Enabled           bool      `json:"enabled" db:"enabled"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
}

type AddressWhitelist struct {
	ID        string    `json:"id" db:"id"`
	OrgID     string    `json:"org_id" db:"org_id"`
	VaultID   *string   `json:"vault_id,omitempty" db:"vault_id"`
	Address   string    `json:"address" db:"address"`
	Chain     string    `json:"chain" db:"chain"`
	Label     *string   `json:"label,omitempty" db:"label"`
	CreatedBy *string   `json:"created_by,omitempty" db:"created_by"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type AuditEntry struct {
	ID           int64     `json:"id" db:"id"`
	OrgID        string    `json:"org_id" db:"org_id"`
	UserID       *string   `json:"user_id,omitempty" db:"user_id"`
	Action       string    `json:"action" db:"action"`
	ResourceType *string   `json:"resource_type,omitempty" db:"resource_type"`
	ResourceID   *string   `json:"resource_id,omitempty" db:"resource_id"`
	Details      []byte    `json:"details,omitempty" db:"details"`
	IPAddress    *string   `json:"ip_address,omitempty" db:"ip_address"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

type Webhook struct {
	ID        string    `json:"id" db:"id"`
	OrgID     string    `json:"org_id" db:"org_id"`
	URL       string    `json:"url" db:"url"`
	Secret    string    `json:"-" db:"secret"`
	Events    []string  `json:"events" db:"events"`
	Enabled   bool      `json:"enabled" db:"enabled"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type Subscription struct {
	ID               string     `json:"id" db:"id"`
	OrgID            string     `json:"org_id" db:"org_id"`
	WalletID         *string    `json:"wallet_id,omitempty" db:"wallet_id"`
	Name             string     `json:"name" db:"name"`
	ProviderName     *string    `json:"provider_name,omitempty" db:"provider_name"`
	RecipientAddress string     `json:"recipient_address" db:"recipient_address"`
	Chain            string     `json:"chain" db:"chain"`
	Token            *string    `json:"token,omitempty" db:"token"`
	Amount           string     `json:"amount" db:"amount"`
	Currency         string     `json:"currency" db:"currency"`
	Interval         string     `json:"interval" db:"interval"`
	NextPaymentAt    time.Time  `json:"next_payment_at" db:"next_payment_at"`
	LastPaymentAt    *time.Time `json:"last_payment_at,omitempty" db:"last_payment_at"`
	LastTxID         *string    `json:"last_tx_id,omitempty" db:"last_tx_id"`
	Status           string     `json:"status" db:"status"`
	MaxRetries       int        `json:"max_retries" db:"max_retries"`
	RetryCount       int        `json:"retry_count" db:"retry_count"`
	RequireBalance   bool       `json:"require_balance" db:"require_balance"`
	CreatedBy        *string    `json:"created_by,omitempty" db:"created_by"`
	CancelledBy      *string    `json:"cancelled_by,omitempty" db:"cancelled_by"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
	CancelledAt      *time.Time `json:"cancelled_at,omitempty" db:"cancelled_at"`
}

type PaymentRequest struct {
	ID               string     `json:"id" db:"id"`
	OrgID            string     `json:"org_id" db:"org_id"`
	WalletID         *string    `json:"wallet_id,omitempty" db:"wallet_id"`
	RequestToken     string     `json:"request_token" db:"request_token"`
	MerchantName     *string    `json:"merchant_name,omitempty" db:"merchant_name"`
	RecipientAddress string     `json:"recipient_address" db:"recipient_address"`
	Chain            string     `json:"chain" db:"chain"`
	Token            *string    `json:"token,omitempty" db:"token"`
	Amount           string     `json:"amount" db:"amount"`
	Memo             *string    `json:"memo,omitempty" db:"memo"`
	Status           string     `json:"status" db:"status"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	PaidTxID         *string    `json:"paid_tx_id,omitempty" db:"paid_tx_id"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
}

type SmartWallet struct {
	ID                string     `json:"id" db:"id"`
	WalletID          string     `json:"wallet_id" db:"wallet_id"`
	OrgID             string     `json:"org_id" db:"org_id"`
	Chain             string     `json:"chain" db:"chain"`
	ContractAddress   string     `json:"contract_address" db:"contract_address"`
	WalletType        string     `json:"wallet_type" db:"wallet_type"`
	FactoryAddress    *string    `json:"factory_address,omitempty" db:"factory_address"`
	EntrypointAddress *string    `json:"entrypoint_address,omitempty" db:"entrypoint_address"`
	Salt              *string    `json:"salt,omitempty" db:"salt"`
	Owners            []string   `json:"owners" db:"owners"`
	Threshold         int        `json:"threshold" db:"threshold"`
	Status            string     `json:"status" db:"status"`
	DeployedAt        *time.Time `json:"deployed_at,omitempty" db:"deployed_at"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
}
