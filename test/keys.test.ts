import { describe, expect, it } from 'bun:test'
import { SSH_MSG } from '../src/constants'
import {
  formatPublicKey,
  generateHostKey,
  generateHostKeyFiles,
  loadHostKey,
  parseAuthorizedKeys,
  parsePublicKey,
  signatureAlgorithmsFor,
  verifySignature,
} from '../src/keys'
import { SshWriter } from '../src/wire'

describe('host keys', () => {
  it('round-trips a generated key through the OpenSSH private key format', () => {
    const { privateKey, publicKey } = generateHostKeyFiles('test-key')
    expect(privateKey).toStartWith('-----BEGIN OPENSSH PRIVATE KEY-----')

    const loaded = loadHostKey(privateKey)
    const parsed = parsePublicKey(publicKey)!

    expect(loaded.algorithm).toBe('ssh-ed25519')
    expect([...loaded.blob]).toEqual([...parsed.blob])
    expect(parsed.comment).toBe('test-key')
  })

  it('signs data its own public key verifies', () => {
    const { privateKey, publicKey } = generateHostKeyFiles()
    const hostKey = loadHostKey(privateKey)
    const key = parsePublicKey(publicKey)!

    const data = new TextEncoder().encode('exchange hash')
    const signature = new SshWriter().string('ssh-ed25519').string(hostKey.sign(data)).toBuffer()

    expect(verifySignature(key, 'ssh-ed25519', data, signature)).toBe(true)
    expect(verifySignature(key, 'ssh-ed25519', new TextEncoder().encode('other'), signature)).toBe(false)
  })

  it('rejects encrypted private keys with an actionable message', () => {
    // A key file whose cipher is anything but "none" cannot be used as-is.
    const encrypted = [
      '-----BEGIN OPENSSH PRIVATE KEY-----',
      Buffer.concat([
        Buffer.from('openssh-key-v1\0'),
        Buffer.from(new SshWriter().string('aes256-ctr').string('bcrypt').string(new Uint8Array()).uint32(1).toBuffer()),
      ]).toString('base64'),
      '-----END OPENSSH PRIVATE KEY-----',
    ].join('\n')

    expect(() => loadHostKey(encrypted)).toThrow(/encrypted private keys are not supported/)
  })

  it('generates an ephemeral key when asked for one', () => {
    const first = generateHostKey()
    const second = generateHostKey()
    expect(first.blob).not.toEqual(second.blob)
  })
})

describe('authorized keys', () => {
  it('parses a file, skipping blanks and comments', () => {
    const { publicKey } = generateHostKeyFiles('one')
    const other = generateHostKeyFiles('two').publicKey

    const keys = parseAuthorizedKeys(`# a comment\n\n${publicKey}${other}`)
    expect(keys).toHaveLength(2)
    expect(keys.map((key) => key.comment)).toEqual(['one', 'two'])
    expect(formatPublicKey(keys[0]!)).toBe(publicKey.trim())
  })

  it('rejects a line whose algorithm does not match its blob', () => {
    const { publicKey } = generateHostKeyFiles()
    const tampered = publicKey.replace('ssh-ed25519', 'ssh-rsa')
    expect(() => parsePublicKey(tampered)).toThrow(/does not match its blob/)
  })

  it('knows which signature algorithms belong to a key type', () => {
    expect(signatureAlgorithmsFor('ssh-ed25519')).toEqual(['ssh-ed25519'])
    expect(signatureAlgorithmsFor('ssh-rsa')).toEqual(['rsa-sha2-512', 'rsa-sha2-256'])
    expect(signatureAlgorithmsFor('ssh-dss')).toEqual([])
  })
})

describe('signature verification', () => {
  it('refuses a signature whose declared type is not the negotiated one', () => {
    const { privateKey, publicKey } = generateHostKeyFiles()
    const hostKey = loadHostKey(privateKey)
    const key = parsePublicKey(publicKey)!
    const data = new Uint8Array([SSH_MSG.USERAUTH_REQUEST])

    const mislabeled = new SshWriter().string('rsa-sha2-256').string(hostKey.sign(data)).toBuffer()
    expect(verifySignature(key, 'ssh-ed25519', data, mislabeled)).toBe(false)
  })

  it('returns false rather than throwing on a malformed signature', () => {
    const { publicKey } = generateHostKeyFiles()
    const key = parsePublicKey(publicKey)!
    const garbage = new SshWriter().string('ssh-ed25519').string(new Uint8Array(8)).toBuffer()
    expect(verifySignature(key, 'ssh-ed25519', new Uint8Array([1]), garbage)).toBe(false)
  })
})
