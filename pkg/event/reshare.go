package event

import "github.com/fystack/mpcium/pkg/types"

type ResharingSuccessEvent struct {
	WalletID     string        `json:"wallet_id"`
	NewThreshold int           `json:"new_threshold"`
	KeyType      types.KeyType `json:"key_type"`
	PubKey       []byte        `json:"pub_key"`
}
