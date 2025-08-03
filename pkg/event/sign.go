package event

const (
	SigningPublisherStream     = "mpc-signing"
	SigningConsumerStream      = "mpc-signing-consumer"
	SigningRequestTopic        = "mpc.signing_request.*"
	SigningResultTopic         = "mpc.mpc_signing_result.*"
	SigningResultCompleteTopic = "mpc.mpc_signing_result.complete"
)

type SigningResultEvent struct {
	ResultType          ResultType `json:"result_type"`
	ErrorCode           ErrorCode  `json:"error_code"`
	ErrorReason         string     `json:"error_reason"`
	IsTimeout           bool       `json:"is_timeout"`
	NetworkInternalCode string     `json:"network_internal_code"`
	WalletID            string     `json:"wallet_id"`
	TxID                string     `json:"tx_id"`
	R                   []byte     `json:"r"`
	S                   []byte     `json:"s"`
	SignatureRecovery   []byte     `json:"signature_recovery"`

	// TODO: define two separate events for eddsa and ecdsa
	Signature []byte `json:"signature"`
}

func CreateSignSuccess(sessionID, walletID, r, s string, metadata map[string]any) SigningResultEvent {
	return SigningResultEvent{
		ResultType:          ResultTypeSuccess,
		ErrorCode:           "",
		WalletID:            walletID,
		TxID:                sessionID,
		R:                   []byte(r),
		S:                   []byte(s),
		NetworkInternalCode: "",
	}
}

func CreateSignFailure(sessionID, walletID string, metadata map[string]any) SigningResultEvent {
	errorReason := ""
	if err, ok := metadata["error"]; ok {
		errorReason = err.(string)
	}

	return SigningResultEvent{
		ResultType:          ResultTypeError,
		ErrorCode:           ErrorCodeSigningFailure,
		ErrorReason:         errorReason,
		WalletID:            walletID,
		TxID:                sessionID,
		NetworkInternalCode: "",
	}
}

type SigningResultSuccessEvent struct {
	NetworkInternalCode string `json:"network_internal_code"`
	WalletID            string `json:"wallet_id"`
	TxID                string `json:"tx_id"`
	R                   []byte `json:"r"`
	S                   []byte `json:"s"`
	SignatureRecovery   []byte `json:"signature_recovery"`

	// TODO: define two separate events for eddsa and ecdsa
	Signature []byte `json:"signature"`
}

type SigningResultErrorEvent struct {
	NetworkInternalCode string    `json:"network_internal_code"`
	WalletID            string    `json:"wallet_id"`
	TxID                string    `json:"tx_id"`
	ErrorCode           ErrorCode `json:"error_code"`
	ErrorReason         string    `json:"error_reason"`
	IsTimeout           bool      `json:"is_timeout"`
}
