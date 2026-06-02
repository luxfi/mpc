package approval

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// NewProvider constructs an ApprovalProvider by name. Configuration is
// passed as a map[string]string so the factory stays orthogonal to the
// concrete provider's option struct — the provider parses what it needs.
//
// Supported provider types:
//
//	ledger-enterprise — Ledger Enterprise (Vault) REST, ECDSA-P256 attestations
//	ledger-device     — USB Ledger Nano via APDU, secp256k1 / Ed25519
//	webauthn          — FIDO2 / passkey, ES256
//	aws-kms           — AWS KMS asymmetric ECDSA via luxfi/hsm
//	gcp-kms           — Google Cloud KMS via luxfi/hsm
//	azure-keyvault    — Azure Key Vault via luxfi/hsm
//	zymbit            — Zymbit SCM via luxfi/hsm
//	yubihsm           — Yubico YubiHSM 2 via luxfi/hsm
//	mldsa             — Post-quantum ML-DSA-65 via luxfi/hsm
//	safe-multisig     — Gnosis Safe execTransaction, on-chain approval
//	local-dev         — Software Ed25519 (test only; refuses production)
//
// Production safety: providers that hold a private key only acceptable in
// non-prod environments (currently only "local-dev") refuse to start when
// MPC_ENV=production.
func NewProvider(providerType string, config map[string]string) (ApprovalProvider, error) {
	providerType = strings.TrimSpace(strings.ToLower(providerType))
	switch providerType {
	case "ledger-enterprise":
		return NewLedgerEnterprise(config)
	case "ledger-device":
		return NewLedgerDevice(config)
	case "webauthn":
		return NewWebAuthn(config)
	case "aws-kms":
		return NewAWSKMS(config)
	case "gcp-kms":
		return NewGCPKMS(config)
	case "azure-keyvault":
		return NewAzureKeyVault(config)
	case "zymbit":
		return NewZymbit(config)
	case "yubihsm", "yubico", "yubi":
		return NewYubiHSM(config)
	case "mldsa":
		return NewMLDSA(config)
	case "safe-multisig":
		return NewSafeMultisig(config)
	case "local-dev":
		if env := strings.ToLower(os.Getenv("MPC_ENV")); env == "production" || env == "prod" {
			return nil, errors.New("approval: local-dev provider forbidden in production (MPC_ENV=" + env + ")")
		}
		return NewLocalDev(config)
	default:
		return nil, fmt.Errorf("approval: unknown provider %q (supported: ledger-enterprise, ledger-device, webauthn, aws-kms, gcp-kms, azure-keyvault, zymbit, yubihsm, mldsa, safe-multisig, local-dev)", providerType)
	}
}

// errNotImplemented is returned by providers that ship as documented stubs
// pending vendor-SDK or hardware availability. Callers MUST treat this as a
// hard failure — never as "approved by default".
var errNotImplemented = errors.New("approval: provider not implemented in this build (see provider docs for shipping plan)")

// ErrNotImplemented exposes the sentinel for callers that want to detect the
// stub case (e.g. fall back to a different provider for the same approver).
func ErrNotImplemented() error { return errNotImplemented }
