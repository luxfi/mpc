// Browser <-> server WebAuthn glue. Translates the server's base64url-encoded
// PublicKeyCredentialCreationOptions into the browser's required ArrayBuffer
// shapes, runs navigator.credentials.create(), and serializes the result back
// to base64url for the /webauthn/register/complete endpoint.

import type { WebAuthnRegisterOptions, WebAuthnRegisterComplete } from './api'

function b64urlToBuffer(b64: string): ArrayBuffer {
  // Backend uses base64.URLEncoding (with padding). atob accepts standard alphabet,
  // so map -/_ to +// and let atob ignore padding.
  const std = b64.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(std)
  const buf = new ArrayBuffer(bin.length)
  const view = new Uint8Array(buf)
  for (let i = 0; i < bin.length; i++) view[i] = bin.charCodeAt(i)
  return buf
}

function bytesToB64url(bytes: ArrayBuffer | Uint8Array): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let bin = ''
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i])
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_')
}

export async function runWebAuthnRegister(
  options: WebAuthnRegisterOptions,
  deviceName: string,
): Promise<WebAuthnRegisterComplete> {
  if (!('credentials' in navigator)) {
    throw new Error('WebAuthn unsupported in this browser')
  }

  const publicKey: PublicKeyCredentialCreationOptions = {
    challenge: b64urlToBuffer(options.challenge),
    rp: { id: options.rp.id, name: options.rp.name },
    user: {
      id: b64urlToBuffer(options.user.id),
      name: options.user.name,
      displayName: options.user.displayName,
    },
    pubKeyCredParams: options.pubKeyCredParams.map((p) => ({
      type: p.type as PublicKeyCredentialType,
      alg: p.alg,
    })),
    timeout: options.timeout,
    attestation: options.attestation as AttestationConveyancePreference,
    authenticatorSelection: {
      authenticatorAttachment: options.authenticatorSelection.authenticatorAttachment as AuthenticatorAttachment,
      userVerification: options.authenticatorSelection.userVerification as UserVerificationRequirement,
      residentKey: options.authenticatorSelection.residentKey as ResidentKeyRequirement,
    },
  }

  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null
  if (!cred) throw new Error('No credential returned by authenticator')

  const att = cred.response as AuthenticatorAttestationResponse
  return {
    credential_id: options.credential_id,
    id: cred.id,
    rawId: bytesToB64url(cred.rawId),
    type: cred.type,
    response: {
      attestationObject: bytesToB64url(att.attestationObject),
      clientDataJSON: bytesToB64url(att.clientDataJSON),
    },
    device_name: deviceName,
  }
}
