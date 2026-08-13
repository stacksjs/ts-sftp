/**
 * SSH key handling: host keys the server presents, and the user public keys it
 * authenticates against.
 *
 * Keys are Ed25519 — the format every current client supports and the only one
 * with no parameter choices to get wrong. User keys may also be RSA, since
 * plenty of existing `authorized_keys` entries still are.
 */

import type { KeyObject } from 'node:crypto'
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto'
import { concat, SshReader, SshWriter } from './wire'

/** DER prefixes for wrapping raw 32-byte keys so node:crypto will import them. */
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
])
const ED25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
])

/** A parsed SSH public key, ready to be compared against or verified with. */
export interface SshPublicKey {
  /** Key algorithm as it appears on the wire, e.g. `ssh-ed25519`. */
  algorithm: string
  /** The SSH-encoded public key blob. */
  blob: Uint8Array
  /** Optional comment from the `authorized_keys` line. */
  comment?: string
}

/** An Ed25519 host key the server signs the key exchange with. */
export interface HostKey {
  algorithm: 'ssh-ed25519'
  /** SSH-encoded public key blob, sent to the client during KEX. */
  blob: Uint8Array
  sign: (data: Uint8Array) => Uint8Array
}

function edPrivateKeyFromSeed(seed: Uint8Array): KeyObject {
  return createPrivateKey({ key: Buffer.from(concat(ED25519_PKCS8_PREFIX, seed)), format: 'der', type: 'pkcs8' })
}

function edPublicKeyFromRaw(raw: Uint8Array): KeyObject {
  return createPublicKey({ key: Buffer.from(concat(ED25519_SPKI_PREFIX, raw)), format: 'der', type: 'spki' })
}

/** Extract the raw 32-byte public key from an Ed25519 KeyObject. */
function edRawPublicKey(key: KeyObject): Uint8Array {
  const spki = new Uint8Array(key.export({ format: 'der', type: 'spki' }))
  return spki.subarray(spki.length - 32)
}

/** The SSH public key blob for an Ed25519 key: `string "ssh-ed25519" || string key`. */
function edPublicKeyBlob(raw: Uint8Array): Uint8Array {
  return new SshWriter().string('ssh-ed25519').string(raw).toBuffer()
}

function base64Decode(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'base64'))
}

function base64Encode(value: Uint8Array): string {
  return Buffer.from(value).toString('base64')
}

/** Generate a fresh Ed25519 host key. */
export function generateHostKey(): HostKey {
  const { privateKey } = generateKeyPairSync('ed25519')
  return hostKeyFromPrivate(privateKey)
}

function hostKeyFromPrivate(privateKey: KeyObject): HostKey {
  const raw = edRawPublicKey(createPublicKey(privateKey))
  return {
    algorithm: 'ssh-ed25519',
    blob: edPublicKeyBlob(raw),
    sign: (data) => new Uint8Array(sign(null, Buffer.from(data), privateKey)),
  }
}

/**
 * Parse a private key in OpenSSH's `openssh-key-v1` format — what `ssh-keygen`
 * writes. Only unencrypted Ed25519 keys are supported; anything else is a
 * clear error rather than a silent fallback.
 */
export function parseOpenSshPrivateKey(pem: string): HostKey {
  const match = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+?)-----END OPENSSH PRIVATE KEY-----/.exec(pem)
  if (!match) throw new Error('ssh: not an OpenSSH private key')

  const body = base64Decode(match[1]!.replace(/\s+/g, ''))
  const magic = new TextDecoder().decode(body.subarray(0, 15))
  if (magic !== 'openssh-key-v1\0') throw new Error('ssh: unsupported private key format')

  const reader = new SshReader(body, 15)
  const cipher = reader.utf8()
  const kdf = reader.utf8()
  reader.string() // kdf options
  const keyCount = reader.uint32()

  if (cipher !== 'none' || kdf !== 'none')
    throw new Error('ssh: encrypted private keys are not supported — decrypt it first with `ssh-keygen -p`')
  if (keyCount !== 1) throw new Error(`ssh: expected exactly one key in the file, found ${keyCount}`)

  reader.string() // public key blob, re-derived from the private key below
  const privateSection = new SshReader(reader.string())

  const check1 = privateSection.uint32()
  const check2 = privateSection.uint32()
  if (check1 !== check2) throw new Error('ssh: private key checksum mismatch — the file may be corrupt')

  const type = privateSection.utf8()
  if (type !== 'ssh-ed25519') throw new Error(`ssh: unsupported host key type ${type} — use an Ed25519 key`)

  privateSection.string() // public key
  const secret = privateSection.string() // seed || public key

  return hostKeyFromPrivate(edPrivateKeyFromSeed(secret.subarray(0, 32)))
}

/** Load a host key from PEM/OpenSSH text. */
export function loadHostKey(text: string): HostKey {
  if (text.includes('BEGIN OPENSSH PRIVATE KEY')) return parseOpenSshPrivateKey(text)

  const key = createPrivateKey(text)
  if (key.asymmetricKeyType !== 'ed25519')
    throw new Error(`ssh: unsupported host key type ${key.asymmetricKeyType ?? 'unknown'} — use an Ed25519 key`)
  return hostKeyFromPrivate(key)
}

/** Serialize a host key pair as an unencrypted OpenSSH private key file. */
export function encodeOpenSshPrivateKey(privateKey: KeyObject, comment = 'ts-sftp'): string {
  const raw = edRawPublicKey(createPublicKey(privateKey))
  const pkcs8 = new Uint8Array(privateKey.export({ format: 'der', type: 'pkcs8' }))
  const seed = pkcs8.subarray(pkcs8.length - 32)
  const publicBlob = edPublicKeyBlob(raw)

  const check = new Uint8Array(4)
  crypto.getRandomValues(check)
  const checkValue = new DataView(check.buffer).getUint32(0, false)

  const secret = new SshWriter()
    .uint32(checkValue)
    .uint32(checkValue)
    .string('ssh-ed25519')
    .string(raw)
    .string(concat(seed, raw))
    .string(comment)

  // The private section is padded to the cipher block size with 1, 2, 3, ...
  let padded = secret.toBuffer()
  for (let i = 1; padded.length % 8 !== 0; i++) padded = concat(padded, new Uint8Array([i]))

  const body = concat(
    new TextEncoder().encode('openssh-key-v1\0'),
    new SshWriter().string('none').string('none').string(new Uint8Array(0)).uint32(1).string(publicBlob).string(padded)
      .toBuffer(),
  )

  const lines = base64Encode(body).match(/.{1,70}/g) ?? []
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${lines.join('\n')}\n-----END OPENSSH PRIVATE KEY-----\n`
}

/** Generate an Ed25519 key pair as OpenSSH-format text, for `ts-sftp keygen`. */
export function generateHostKeyFiles(comment = 'ts-sftp'): { privateKey: string; publicKey: string } {
  const { privateKey } = generateKeyPairSync('ed25519')
  const raw = edRawPublicKey(createPublicKey(privateKey))
  return {
    privateKey: encodeOpenSshPrivateKey(privateKey, comment),
    publicKey: `ssh-ed25519 ${base64Encode(edPublicKeyBlob(raw))} ${comment}\n`,
  }
}

/**
 * Parse one `authorized_keys` line: `<algorithm> <base64 blob> [comment]`.
 * Returns undefined for blank lines and comments so whole files can be mapped.
 */
export function parsePublicKey(line: string): SshPublicKey | undefined {
  const trimmed = line.trim()
  if (!trimmed || trimmed.startsWith('#')) return undefined

  const parts = trimmed.split(/\s+/)
  if (parts.length < 2) throw new Error(`ssh: malformed public key: ${trimmed.slice(0, 40)}`)

  const [algorithm, encoded, ...rest] = parts as [string, string, ...string[]]
  const blob = base64Decode(encoded)
  const declared = new SshReader(blob).utf8()
  if (declared !== algorithm)
    throw new Error(`ssh: public key algorithm ${algorithm} does not match its blob (${declared})`)

  return { algorithm, blob, comment: rest.join(' ') || undefined }
}

/** Parse every key in an `authorized_keys` file. */
export function parseAuthorizedKeys(text: string): SshPublicKey[] {
  return text
    .split('\n')
    .map((line) => parsePublicKey(line))
    .filter((key): key is SshPublicKey => key !== undefined)
}

/** Render a public key blob as an `authorized_keys` line. */
export function formatPublicKey(key: SshPublicKey): string {
  return `${key.algorithm} ${base64Encode(key.blob)}${key.comment ? ` ${key.comment}` : ''}`
}

function rsaPublicKeyFromBlob(blob: Uint8Array): KeyObject {
  const reader = new SshReader(blob)
  reader.utf8() // "ssh-rsa"
  const e = reader.string()
  const n = reader.string()

  const toBase64Url = (value: Uint8Array): string => {
    let start = 0
    while (start < value.length - 1 && value[start] === 0) start++
    return Buffer.from(value.subarray(start)).toString('base64url')
  }

  return createPublicKey({
    key: { kty: 'RSA', n: toBase64Url(n), e: toBase64Url(e) },
    format: 'jwk',
  })
}

/**
 * Verify a user authentication signature.
 *
 * `algorithm` is the signature algorithm the client negotiated, which for RSA
 * keys differs from the key's own type (`ssh-rsa` keys sign as `rsa-sha2-256`
 * or `rsa-sha2-512`).
 */
export function verifySignature(
  key: SshPublicKey,
  algorithm: string,
  data: Uint8Array,
  signatureBlob: Uint8Array,
): boolean {
  const reader = new SshReader(signatureBlob)
  const signatureType = reader.utf8()
  const signature = reader.string()
  if (signatureType !== algorithm) return false

  try {
    if (key.algorithm === 'ssh-ed25519') {
      if (algorithm !== 'ssh-ed25519') return false
      const raw = new SshReader(key.blob)
      raw.utf8()
      return verify(null, Buffer.from(data), edPublicKeyFromRaw(raw.string()), Buffer.from(signature))
    }

    if (key.algorithm === 'ssh-rsa') {
      const hash = algorithm === 'rsa-sha2-512' ? 'sha512' : algorithm === 'rsa-sha2-256' ? 'sha256' : undefined
      if (!hash) return false
      return verify(hash, Buffer.from(data), rsaPublicKeyFromBlob(key.blob), Buffer.from(signature))
    }
  }
  catch {
    return false
  }

  return false
}

/** Signature algorithms a client may use with a given public key type. */
export function signatureAlgorithmsFor(keyAlgorithm: string): string[] {
  if (keyAlgorithm === 'ssh-ed25519') return ['ssh-ed25519']
  if (keyAlgorithm === 'ssh-rsa') return ['rsa-sha2-512', 'rsa-sha2-256']
  return []
}
