/**
 * Key exchange: `curve25519-sha256` (RFC 8731) with an Ed25519 host key.
 *
 * One method, one host key type, one cipher — a client either speaks modern
 * crypto or it does not connect. That keeps the negotiation table short and
 * leaves no legacy algorithm to accidentally fall back to.
 */

import type { HostKey } from './keys'
import type { AeadKeys } from './packet'
import { createHash, createPublicKey, diffieHellman, generateKeyPairSync } from 'node:crypto'
import { concat, SshWriter } from './wire'

const X25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
])

/** Algorithms this server offers, in preference order. */
export const KEX_ALGORITHMS: string[] = ['curve25519-sha256', 'curve25519-sha256@libssh.org']
export const HOST_KEY_ALGORITHMS: string[] = ['ssh-ed25519']
export const CIPHERS: string[] = ['aes256-gcm@openssh.com']
/** Implicit with an AEAD cipher, but the field must still be negotiated. */
export const MACS: string[] = ['aes256-gcm@openssh.com']
export const COMPRESSION: string[] = ['none']

/** The inputs the exchange hash is computed over. */
export interface ExchangeHashInput {
  clientVersion: string
  serverVersion: string
  clientKexInit: Uint8Array
  serverKexInit: Uint8Array
  hostKeyBlob: Uint8Array
  clientPublicKey: Uint8Array
  serverPublicKey: Uint8Array
  sharedSecret: Uint8Array
}

/** The result of a completed exchange. */
export interface KexResult {
  exchangeHash: Uint8Array
  signature: Uint8Array
  serverPublicKey: Uint8Array
  sharedSecret: Uint8Array
}

/** An ephemeral X25519 key pair for one exchange. */
export function generateEphemeralKeyPair(): { publicKey: Uint8Array; derive: (peer: Uint8Array) => Uint8Array } {
  const { publicKey, privateKey } = generateKeyPairSync('x25519')
  const spki = new Uint8Array(publicKey.export({ format: 'der', type: 'spki' }))

  return {
    publicKey: spki.subarray(spki.length - 32),
    derive: (peer) => {
      if (peer.length !== 32) throw new Error('ssh: peer key exchange value must be 32 bytes')
      const peerKey = createPublicKey({
        key: Buffer.from(concat(X25519_SPKI_PREFIX, peer)),
        format: 'der',
        type: 'spki',
      })
      const secret = new Uint8Array(diffieHellman({ privateKey, publicKey: peerKey }))
      // An all-zero shared secret means a small-order peer key, i.e. an attempt
      // to force a known secret.
      if (secret.every((byte) => byte === 0)) throw new Error('ssh: peer contributed a degenerate key exchange value')
      return secret
    },
  }
}

/** H = hash(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K) */
export function computeExchangeHash(input: ExchangeHashInput): Uint8Array {
  const writer = new SshWriter()
    .string(input.clientVersion)
    .string(input.serverVersion)
    .string(input.clientKexInit)
    .string(input.serverKexInit)
    .string(input.hostKeyBlob)
    .string(input.clientPublicKey)
    .string(input.serverPublicKey)
    .mpint(input.sharedSecret)

  return new Uint8Array(createHash('sha256').update(writer.toBuffer()).digest())
}

/**
 * Derive one key stream (RFC 4253 §7.2):
 * `K1 = HASH(K || H || X || session_id)`, extended by hashing K || H || K1…
 */
export function deriveKey(
  sharedSecret: Uint8Array,
  exchangeHash: Uint8Array,
  letter: 'A' | 'B' | 'C' | 'D' | 'E' | 'F',
  sessionId: Uint8Array,
  length: number,
): Uint8Array {
  const secret = new SshWriter().mpint(sharedSecret).toBuffer()

  let material: Uint8Array = new Uint8Array(
    createHash('sha256')
      .update(concat(secret, exchangeHash, new TextEncoder().encode(letter), sessionId))
      .digest(),
  )

  while (material.length < length) {
    const next = new Uint8Array(createHash('sha256').update(concat(secret, exchangeHash, material)).digest())
    material = concat(material, next)
  }

  return material.subarray(0, length)
}

/** The cipher keys for both directions, derived from a completed exchange. */
export function deriveSessionKeys(
  sharedSecret: Uint8Array,
  exchangeHash: Uint8Array,
  sessionId: Uint8Array,
): { clientToServer: AeadKeys; serverToClient: AeadKeys } {
  return {
    clientToServer: {
      iv: deriveKey(sharedSecret, exchangeHash, 'A', sessionId, 12),
      key: deriveKey(sharedSecret, exchangeHash, 'C', sessionId, 32),
    },
    serverToClient: {
      iv: deriveKey(sharedSecret, exchangeHash, 'B', sessionId, 12),
      key: deriveKey(sharedSecret, exchangeHash, 'D', sessionId, 32),
    },
  }
}

/** Sign the exchange hash with the host key, as `string algorithm || string signature`. */
export function signExchangeHash(hostKey: HostKey, exchangeHash: Uint8Array): Uint8Array {
  return new SshWriter().string(hostKey.algorithm).string(hostKey.sign(exchangeHash)).toBuffer()
}

/** Pick the first algorithm the client offers that the server also supports. */
export function negotiate(clientAlgorithms: string[], serverAlgorithms: string[], what: string): string {
  const match = clientAlgorithms.find((algorithm) => serverAlgorithms.includes(algorithm))
  if (!match)
    throw new Error(
      `ssh: no shared ${what} — client offered ${clientAlgorithms.join(', ') || 'nothing'}, server supports ${serverAlgorithms.join(', ')}`,
    )
  return match
}
