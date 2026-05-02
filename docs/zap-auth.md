# ZAP bearer-token gate (LP-103, v1.14.0)

`pkg/zapauth` validates a JWKS-signed JWT presented BEFORE the
existing X25519 + ML-KEM-768 hybrid handshake (`pkg/zap`). Per-peer
verified claims are stored on the connection so downstream handlers
can authorize per-opcode.

## Wire sequence

```
client → server   OpAuthHello   (0x00EF)  zapauth.AuthHelloFrame{ Version=1, Token }
server → client   OpAuthHello              {"ok":true}  | {"error":"..."}
client → server   OpClientHello (0x00F0)  X25519 pub + ML-KEM-768 pub
server → client   OpServerHello (0x00F1)  X25519 pub + ML-KEM-768 ct  (rejected with "auth required" when ZAP_AUTH_REQUIRED=true and AuthHello did not validate)
... AEAD-sealed KMS ops ...
```

`OpAuthHello` body layout (little-endian):

```
+0   uint8  version           // CurrentFrameVersion = 1
+1   uint16 token_len
+3   [token_len]byte token
```

Tokens above 64 KiB are rejected at marshal time.

## Server configuration (`mpcd`)

| Env var                    | Required when            | Default                                                   |
|----------------------------|--------------------------|-----------------------------------------------------------|
| `ZAP_JWKS_URL`             | enabling auth            | unset (auth disabled)                                     |
| `ZAP_EXPECTED_ISS`         | `ZAP_JWKS_URL` set       | unset (init fails)                                        |
| `ZAP_EXPECTED_AUDIENCES`   | `ZAP_JWKS_URL` set       | unset (init fails) — comma-separated allow-list           |
| `ZAP_AUTH_REQUIRED`        | optional                 | `false` in v1.14.0; flips to `true` in v1.15.0 by default |

When `ZAP_JWKS_URL` is unset the server starts with `auth=off` and
behaves exactly like v1.13.x. When set without `ZAP_AUTH_REQUIRED=true`
the server starts with `auth=advisory`: it verifies submitted tokens,
attaches claims, logs a WARN for unauthenticated peers, and still
serves them. With `ZAP_AUTH_REQUIRED=true` (`auth=required`) every
opcode dispatch checks for attached claims and rejects unauthenticated
peers with `{"error":"auth required"}`.

## Tokens

JWT requirements:
- alg ∈ { RS256, RS384, RS512, ES256, ES384, ES512, EdDSA }
- kid resolves against the JWKS document (cached 5 minutes)
- iss exactly matches `ZAP_EXPECTED_ISS`
- aud contains at least one entry in `ZAP_EXPECTED_AUDIENCES`
- exp is in the future

ECDSA signatures may be encoded as ASN.1 (RFC 3279) or fixed-width
R||S (RFC 7518 §3.4 — what real JWTs emit).

## Backwards compatibility

- v1.13.x clients that never send `OpAuthHello` keep working in
  `auth=off` and `auth=advisory` modes.
- v1.14.x clients that send `OpAuthHello` against a v1.13.x server
  receive an "unknown opcode" error and may proceed plaintext.
- The flip to `ZAP_AUTH_REQUIRED=true` happens after every KMS
  deployment ships with a build that mints the bearer
  (`luxfi/kms` v1.9.0 + `pkg/iamclient`).
