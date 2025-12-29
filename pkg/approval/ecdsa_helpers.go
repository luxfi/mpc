package approval

import (
	"encoding/asn1"
	"errors"
	"math/big"
)

// ecdsaSig is the ASN.1 SEQUENCE { r INTEGER, s INTEGER } that ecdsa.VerifyASN1
// expects.
type ecdsaSig struct {
	R, S *big.Int
}

// ecdsaRawToASN1 converts a raw P-256 r||s signature (64 bytes) to ASN.1 DER.
// Azure Key Vault and some FIDO2 authenticators return raw signatures; AWS
// KMS / Google Cloud KMS / OpenSSL return DER. The approval package
// normalizes to DER so all ECDSA verification uses ecdsa.VerifyASN1.
func ecdsaRawToASN1(raw []byte) ([]byte, error) {
	if len(raw) != 64 {
		return nil, errors.New("ecdsa: raw signature must be 64 bytes (r||s for P-256)")
	}
	sig := ecdsaSig{
		R: new(big.Int).SetBytes(raw[:32]),
		S: new(big.Int).SetBytes(raw[32:]),
	}
	return asn1.Marshal(sig)
}

// ecdsaASN1ToRaw converts an ASN.1 DER signature to raw r||s. Used when the
// destination expects raw form (some on-chain verifiers).
func ecdsaASN1ToRaw(der []byte) ([]byte, error) {
	var sig ecdsaSig
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()
	copy(out[32-len(rBytes):32], rBytes)
	copy(out[64-len(sBytes):], sBytes)
	return out, nil
}

// marshalECDSASig wraps asn1.Marshal so callers do not have to import
// encoding/asn1 themselves. The output is the same SEQUENCE { r, s }
// that ecdsa.VerifyASN1 expects.
func marshalECDSASig(sig ecdsaSig) ([]byte, error) {
	return asn1.Marshal(sig)
}
