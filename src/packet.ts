/**
 * The SSH binary packet protocol (RFC 4253 §6).
 *
 * Before key exchange completes, packets travel in the clear. Afterwards they
 * are sealed with `aes256-gcm@openssh.com` (RFC 5647), where the length field
 * stays in the clear as additional authenticated data and the tag replaces a
 * separate MAC.
 */

import { createCipheriv, createDecipheriv, randomFillSync } from 'node:crypto'
import { concat } from './wire'

const GCM_TAG_LENGTH = 16
const GCM_BLOCK_SIZE = 16
const PLAIN_BLOCK_SIZE = 8
const MIN_PADDING = 4

/** Largest packet we will accept, matching OpenSSH's limit. */
export const MAX_PACKET_LENGTH: number = 256 * 1024

/** Keys for one direction of an `aes256-gcm@openssh.com` stream. */
export interface AeadKeys {
  key: Uint8Array
  iv: Uint8Array
}

/** A packet decoded off the wire, with how many bytes it consumed. */
export interface DecodedPacket {
  payload: Uint8Array
  consumed: number
}

/**
 * The GCM invocation counter: a fixed 4-byte field followed by an 8-byte
 * counter incremented once per packet.
 */
function incrementIv(iv: Uint8Array): void {
  for (let i = 11; i >= 4; i--) {
    iv[i] = (iv[i]! + 1) & 0xff
    if (iv[i] !== 0) return
  }
}

/** Encodes and decodes packets for one connection, in whichever mode is active. */
export class PacketCodec {
  private outgoing?: AeadKeys
  private incoming?: AeadKeys
  sendSequence = 0
  receiveSequence = 0

  /** Switch the outgoing direction to authenticated encryption. */
  setOutgoingKeys(keys: AeadKeys): void {
    this.outgoing = { key: keys.key, iv: new Uint8Array(keys.iv) }
  }

  /** Switch the incoming direction to authenticated encryption. */
  setIncomingKeys(keys: AeadKeys): void {
    this.incoming = { key: keys.key, iv: new Uint8Array(keys.iv) }
  }

  get encrypted(): boolean {
    return this.outgoing !== undefined
  }

  encode(payload: Uint8Array): Uint8Array {
    const blockSize = this.outgoing ? GCM_BLOCK_SIZE : PLAIN_BLOCK_SIZE
    // The length field is covered by the block alignment only when it is
    // encrypted, which for GCM it is not.
    const unaligned = this.outgoing ? 1 + payload.length : 4 + 1 + payload.length

    let padding = blockSize - (unaligned % blockSize)
    if (padding < MIN_PADDING) padding += blockSize

    const padBytes = new Uint8Array(padding)
    randomFillSync(padBytes)

    const packetLength = 1 + payload.length + padding
    const lengthField = new Uint8Array(4)
    new DataView(lengthField.buffer).setUint32(0, packetLength, false)
    const body = concat(new Uint8Array([padding]), payload, padBytes)

    this.sendSequence = (this.sendSequence + 1) >>> 0

    if (!this.outgoing) return concat(lengthField, body)

    const cipher = createCipheriv('aes-256-gcm', this.outgoing.key, this.outgoing.iv, { authTagLength: GCM_TAG_LENGTH })
    cipher.setAAD(lengthField)
    const sealed = concat(new Uint8Array(cipher.update(body)), new Uint8Array(cipher.final()))
    const tag = new Uint8Array(cipher.getAuthTag())
    incrementIv(this.outgoing.iv)

    return concat(lengthField, sealed, tag)
  }

  /** Decode one packet, or return undefined when more bytes are needed. */
  decode(buffer: Uint8Array): DecodedPacket | undefined {
    if (buffer.length < 4) return undefined

    const packetLength = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength).getUint32(0, false)
    if (packetLength < 8 || packetLength > MAX_PACKET_LENGTH)
      throw new Error(`ssh: invalid packet length ${packetLength}`)

    if (!this.incoming) {
      const total = 4 + packetLength
      if (buffer.length < total) return undefined

      const padding = buffer[4]!
      if (padding < MIN_PADDING || padding > packetLength - 1) throw new Error('ssh: invalid padding length')

      this.receiveSequence = (this.receiveSequence + 1) >>> 0
      return { payload: buffer.subarray(5, 4 + packetLength - padding), consumed: total }
    }

    const total = 4 + packetLength + GCM_TAG_LENGTH
    if (buffer.length < total) return undefined
    if (packetLength % GCM_BLOCK_SIZE !== 0) throw new Error('ssh: packet is not block aligned')

    const decipher = createDecipheriv('aes-256-gcm', this.incoming.key, this.incoming.iv, {
      authTagLength: GCM_TAG_LENGTH,
    })
    decipher.setAAD(buffer.subarray(0, 4))
    decipher.setAuthTag(buffer.subarray(4 + packetLength, total))

    let opened: Uint8Array
    try {
      opened = concat(
        new Uint8Array(decipher.update(buffer.subarray(4, 4 + packetLength))),
        new Uint8Array(decipher.final()),
      )
    }
    catch {
      throw new Error('ssh: packet authentication failed')
    }

    incrementIv(this.incoming.iv)
    this.receiveSequence = (this.receiveSequence + 1) >>> 0

    const padding = opened[0]!
    if (padding < MIN_PADDING || padding > opened.length - 1) throw new Error('ssh: invalid padding length')

    return { payload: opened.subarray(1, opened.length - padding), consumed: total }
  }
}
