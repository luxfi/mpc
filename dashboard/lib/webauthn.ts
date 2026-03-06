// WebAuthn/FIDO2 helpers for biometric transaction approval.
// Uses native browser APIs — no npm dependencies.

export function isWebAuthnSupported(): boolean {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential
}

export function bufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function base64urlToBuffer(str: string): ArrayBuffer {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/')
  const padded = base64 + '='.repeat((4 - base64.length % 4) % 4)
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}

export async function sha256(message: string): Promise<ArrayBuffer> {
  const encoder = new TextEncoder()
  return crypto.subtle.digest('SHA-256', encoder.encode(message))
}

export async function startRegistration(options: any): Promise<any> {
  const publicKey: PublicKeyCredentialCreationOptions = {
    challenge: base64urlToBuffer(options.challenge),
    rp: options.rp,
    user: {
      id: base64urlToBuffer(options.user.id),
      name: options.user.name,
      displayName: options.user.displayName,
    },
    pubKeyCredParams: options.pubKeyCredParams,
    timeout: options.timeout || 60000,
    attestation: options.attestation || 'direct',
    authenticatorSelection: options.authenticatorSelection,
  }

  const credential = await navigator.credentials.create({ publicKey }) as PublicKeyCredential
  if (!credential) throw new Error('Registration cancelled')

  const response = credential.response as AuthenticatorAttestationResponse
  return {
    credential_id: options.credential_id,
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bufferToBase64url(response.attestationObject),
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
    },
  }
}

export async function startAuthentication(txId: string): Promise<any> {
  const challengeBuffer = await sha256(txId)

  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: challengeBuffer,
    timeout: 60000,
    userVerification: 'required',
    rpId: 'lux.network',
  }

  const assertion = await navigator.credentials.get({ publicKey }) as PublicKeyCredential
  if (!assertion) throw new Error('Authentication cancelled')

  const response = assertion.response as AuthenticatorAssertionResponse
  return {
    id: assertion.id,
    rawId: bufferToBase64url(assertion.rawId),
    type: assertion.type,
    response: {
      authenticatorData: bufferToBase64url(response.authenticatorData),
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      signature: bufferToBase64url(response.signature),
      userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : '',
    },
  }
}
