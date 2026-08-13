/**
 * SSH wire encoding (RFC 4251 §5).
 *
 * Every field on the wire is one of: a byte, a uint32/uint64 in network order,
 * a `string` (uint32 length followed by that many bytes — binary, not
 * necessarily text), an mpint (a two's-complement big integer), or a name-list
 * (a comma-separated string).
 */

/** Sequential writer producing an SSH-encoded buffer. */
export class SshWriter {
  private chunks: Uint8Array[] = []
  private length = 0

  byte(value: number): this {
    return this.raw(new Uint8Array([value & 0xff]))
  }

  boolean(value: boolean): this {
    return this.byte(value ? 1 : 0)
  }

  uint32(value: number): this {
    const buf = new Uint8Array(4)
    new DataView(buf.buffer).setUint32(0, value >>> 0, false)
    return this.raw(buf)
  }

  uint64(value: number | bigint): this {
    const buf = new Uint8Array(8)
    new DataView(buf.buffer).setBigUint64(0, BigInt(value), false)
    return this.raw(buf)
  }

  /** A length-prefixed string. Text is encoded as UTF-8. */
  string(value: Uint8Array | string): this {
    const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value
    this.uint32(bytes.length)
    return this.raw(bytes)
  }

  nameList(values: string[]): this {
    return this.string(values.join(','))
  }

  /**
   * A multiple-precision integer: minimal length, two's complement, with a
   * leading zero byte when the high bit would otherwise read as negative.
   */
  mpint(value: Uint8Array): this {
    let start = 0
    while (start < value.length - 1 && value[start] === 0) start++
    const trimmed = value.subarray(start)

    if (trimmed.length === 1 && trimmed[0] === 0) return this.string(new Uint8Array(0))
    if (trimmed[0]! & 0x80) {
      const padded = new Uint8Array(trimmed.length + 1)
      padded.set(trimmed, 1)
      return this.string(padded)
    }
    return this.string(trimmed)
  }

  /** Append bytes with no length prefix. */
  raw(bytes: Uint8Array): this {
    this.chunks.push(bytes)
    this.length += bytes.length
    return this
  }

  toBuffer(): Uint8Array {
    const out = new Uint8Array(this.length)
    let offset = 0
    for (const chunk of this.chunks) {
      out.set(chunk, offset)
      offset += chunk.length
    }
    return out
  }
}

/** Sequential reader over an SSH-encoded buffer. */
export class SshReader {
  private offset: number
  private readonly view: DataView

  constructor(
    private readonly buffer: Uint8Array,
    offset = 0,
  ) {
    this.offset = offset
    this.view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength)
  }

  get position(): number {
    return this.offset
  }

  get remaining(): number {
    return this.buffer.length - this.offset
  }

  private require(bytes: number): void {
    if (this.remaining < bytes) throw new Error(`ssh: truncated packet, wanted ${bytes} bytes, have ${this.remaining}`)
  }

  byte(): number {
    this.require(1)
    return this.buffer[this.offset++]!
  }

  boolean(): boolean {
    return this.byte() !== 0
  }

  uint32(): number {
    this.require(4)
    const value = this.view.getUint32(this.offset, false)
    this.offset += 4
    return value
  }

  uint64(): bigint {
    this.require(8)
    const value = this.view.getBigUint64(this.offset, false)
    this.offset += 8
    return value
  }

  string(): Uint8Array {
    const length = this.uint32()
    this.require(length)
    const value = this.buffer.subarray(this.offset, this.offset + length)
    this.offset += length
    return value
  }

  utf8(): string {
    return new TextDecoder().decode(this.string())
  }

  nameList(): string[] {
    const value = this.utf8()
    return value.length === 0 ? [] : value.split(',')
  }

  /** Read `length` bytes with no length prefix. */
  raw(length: number): Uint8Array {
    this.require(length)
    const value = this.buffer.subarray(this.offset, this.offset + length)
    this.offset += length
    return value
  }

  /** Everything not yet consumed. */
  rest(): Uint8Array {
    return this.raw(this.remaining)
  }
}

/** Concatenate byte arrays into one buffer. */
export function concat(...parts: Uint8Array[]): Uint8Array {
  let length = 0
  for (const part of parts) length += part.length
  const out = new Uint8Array(length)
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

/** Constant-time comparison, so key and signature checks leak no timing. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}
