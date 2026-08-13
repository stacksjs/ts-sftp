import { describe, expect, it } from 'bun:test'
import { randomBytes } from 'node:crypto'
import { computeExchangeHash, deriveKey, deriveSessionKeys, generateEphemeralKeyPair, negotiate } from '../src/kex'
import { PacketCodec } from '../src/packet'

function keyPair(): { key: Uint8Array; iv: Uint8Array } {
  return { key: new Uint8Array(randomBytes(32)), iv: new Uint8Array(randomBytes(12)) }
}

describe('binary packet protocol', () => {
  it('round-trips a plaintext packet with valid padding', () => {
    const sender = new PacketCodec()
    const receiver = new PacketCodec()
    const payload = new Uint8Array([20, 1, 2, 3])

    const wire = sender.encode(payload)
    expect(wire.length % 8).toBe(0)

    const decoded = receiver.decode(wire)!
    expect([...decoded.payload]).toEqual([...payload])
    expect(decoded.consumed).toBe(wire.length)
  })

  it('round-trips encrypted packets and keeps the counters in step', () => {
    const clientToServer = keyPair()
    const sender = new PacketCodec()
    const receiver = new PacketCodec()
    sender.setOutgoingKeys(clientToServer)
    receiver.setIncomingKeys(clientToServer)

    for (let i = 0; i < 5; i++) {
      const payload = new Uint8Array(randomBytes(100 + i))
      const decoded = receiver.decode(sender.encode(payload))!
      expect([...decoded.payload]).toEqual([...payload])
    }

    expect(sender.sendSequence).toBe(5)
    expect(receiver.receiveSequence).toBe(5)
  })

  it('rejects a tampered ciphertext', () => {
    const keys = keyPair()
    const sender = new PacketCodec()
    const receiver = new PacketCodec()
    sender.setOutgoingKeys(keys)
    receiver.setIncomingKeys(keys)

    const wire = sender.encode(new Uint8Array([1, 2, 3, 4]))
    wire[10] = wire[10]! ^ 0xff

    expect(() => receiver.decode(wire)).toThrow(/authentication failed/)
  })

  it('waits for the rest of a partial packet', () => {
    const sender = new PacketCodec()
    const receiver = new PacketCodec()
    const wire = sender.encode(new Uint8Array([5, 6, 7]))

    expect(receiver.decode(wire.subarray(0, 3))).toBeUndefined()
    expect(receiver.decode(wire.subarray(0, wire.length - 1))).toBeUndefined()
    expect(receiver.decode(wire)).toBeDefined()
  })

  it('refuses an implausible packet length', () => {
    const receiver = new PacketCodec()
    expect(() => receiver.decode(new Uint8Array([0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]))).toThrow(/invalid packet length/)
    expect(() => receiver.decode(new Uint8Array([0, 0, 0, 1, 0, 0, 0, 0]))).toThrow(/invalid packet length/)
  })
})

describe('key exchange', () => {
  it('derives the same secret on both sides', () => {
    const client = generateEphemeralKeyPair()
    const server = generateEphemeralKeyPair()

    expect([...client.derive(server.publicKey)]).toEqual([...server.derive(client.publicKey)])
  })

  it('rejects a peer value of the wrong size', () => {
    const server = generateEphemeralKeyPair()
    expect(() => server.derive(new Uint8Array(31))).toThrow(/32 bytes/)
  })

  it('computes a hash that changes with every input', () => {
    const base = {
      clientVersion: 'SSH-2.0-client',
      serverVersion: 'SSH-2.0-ts-sftp',
      clientKexInit: new Uint8Array([20, 1]),
      serverKexInit: new Uint8Array([20, 2]),
      hostKeyBlob: new Uint8Array([3]),
      clientPublicKey: new Uint8Array(32).fill(1),
      serverPublicKey: new Uint8Array(32).fill(2),
      sharedSecret: new Uint8Array(32).fill(3),
    }

    const hash = computeExchangeHash(base)
    expect(hash).toHaveLength(32)
    expect(computeExchangeHash(base)).toEqual(hash)
    expect(computeExchangeHash({ ...base, clientVersion: 'SSH-2.0-other' })).not.toEqual(hash)
  })

  it('extends derived key material past one hash block', () => {
    const secret = new Uint8Array(32).fill(7)
    const hash = new Uint8Array(32).fill(9)

    const short = deriveKey(secret, hash, 'A', hash, 12)
    const long = deriveKey(secret, hash, 'A', hash, 64)

    expect(short).toHaveLength(12)
    expect(long).toHaveLength(64)
    expect([...long.subarray(0, 12)]).toEqual([...short])
  })

  it('derives four distinct keys for the two directions', () => {
    const secret = new Uint8Array(32).fill(5)
    const hash = new Uint8Array(32).fill(6)
    const keys = deriveSessionKeys(secret, hash, hash)

    expect(keys.clientToServer.key).toHaveLength(32)
    expect(keys.clientToServer.iv).toHaveLength(12)
    expect(keys.clientToServer.key).not.toEqual(keys.serverToClient.key)
    expect(keys.clientToServer.iv).not.toEqual(keys.serverToClient.iv)
  })

  it('names both sides when negotiation fails', () => {
    expect(negotiate(['a'], ['a', 'b'], 'cipher')).toBe('a')
    expect(() => negotiate(['3des-cbc'], ['aes256-gcm@openssh.com'], 'cipher')).toThrow(
      /no shared cipher — client offered 3des-cbc, server supports aes256-gcm@openssh.com/,
    )
  })
})
