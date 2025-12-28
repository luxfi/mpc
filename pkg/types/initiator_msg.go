package types

import "encoding/json"

type KeyType string

const (
	KeyTypeSecp256k1 KeyType = "secp256k1"
	KeyTypeEd25519   KeyType = "ed25519"
	KeyTypeSR25519   KeyType = "sr25519"
	KeyTypeBLS       KeyType = "bls"
)

// InitiatorMessage is anything that carries a payload to verify and its signature.
type InitiatorMessage interface {
	// Raw returns the canonical byte‐slice that was signed.
	Raw() ([]byte, error)
	// Sig returns the signature over Raw().
	Sig() []byte
	// InitiatorID returns the ID whose public key we have to look up.
	InitiatorID() string
}

type GenerateKeyMessage struct {
	OrgID     string `json:"org_id,omitempty"`
	WalletID  string `json:"wallet_id"`
	Signature []byte `json:"signature"`
}

type SignTxMessage struct {
	OrgID               string  `json:"org_id,omitempty"`
	KeyType             KeyType `json:"key_type"`
	WalletID            string  `json:"wallet_id"`
	NetworkInternalCode string  `json:"network_internal_code"`
	TxID                string  `json:"tx_id"`
	Tx                  []byte  `json:"tx"`
	Signature           []byte  `json:"signature"`
}

type ResharingMessage struct {
	OrgID        string   `json:"org_id,omitempty"`
	SessionID    string   `json:"session_id"`
	NodeIDs      []string `json:"node_ids"` // new peer IDs
	NewThreshold int      `json:"new_threshold"`
	KeyType      KeyType  `json:"key_type"`
	WalletID     string   `json:"wallet_id"`
	Signature    []byte   `json:"signature,omitempty"`
}

func (m *SignTxMessage) Raw() ([]byte, error) {
	// omit the Signature field itself when computing the signed‐over data
	payload := struct {
		OrgID               string  `json:"org_id,omitempty"`
		KeyType             KeyType `json:"key_type"`
		WalletID            string  `json:"wallet_id"`
		NetworkInternalCode string  `json:"network_internal_code"`
		TxID                string  `json:"tx_id"`
		Tx                  []byte  `json:"tx"`
	}{
		OrgID:               m.OrgID,
		KeyType:             m.KeyType,
		WalletID:            m.WalletID,
		NetworkInternalCode: m.NetworkInternalCode,
		TxID:                m.TxID,
		Tx:                  m.Tx,
	}
	return json.Marshal(payload)
}

func (m *SignTxMessage) Sig() []byte {
	return m.Signature
}

func (m *SignTxMessage) InitiatorID() string {
	return m.TxID
}

func (m *GenerateKeyMessage) Raw() ([]byte, error) {
	if m.OrgID != "" {
		return []byte(m.OrgID + ":" + m.WalletID), nil
	}
	return []byte(m.WalletID), nil
}

func (m *GenerateKeyMessage) Sig() []byte {
	return m.Signature
}

func (m *GenerateKeyMessage) InitiatorID() string {
	return m.WalletID
}

func (m *ResharingMessage) Raw() ([]byte, error) {
	copy := *m           // create a shallow copy
	copy.Signature = nil // modify only the copy
	return json.Marshal(&copy)
}

func (m *ResharingMessage) Sig() []byte {
	return m.Signature
}

func (m *ResharingMessage) InitiatorID() string {
	return m.WalletID
}
