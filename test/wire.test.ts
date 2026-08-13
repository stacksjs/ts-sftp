import { describe, expect, it } from 'bun:test'
import { concat, SshReader, SshWriter, timingSafeEqual } from '../src/wire'

describe('ssh wire encoding', () => {
  it('round-trips every field type in order', () => {
    const buffer = new SshWriter()
      .byte(42)
      .boolean(true)
      .uint32(0xdeadbeef)
      .uint64(2n ** 40n)
      .string('hello')
      .nameList(['a', 'b', 'c'])
      .toBuffer()

    const reader = new SshReader(buffer)
    expect(reader.byte()).toBe(42)
    expect(reader.boolean()).toBe(true)
    expect(reader.uint32()).toBe(0xdeadbeef)
    expect(reader.uint64()).toBe(2n ** 40n)
    expect(reader.utf8()).toBe('hello')
    expect(reader.nameList()).toEqual(['a', 'b', 'c'])
    expect(reader.remaining).toBe(0)
  })

  it('encodes an mpint with a leading zero when the high bit is set', () => {
    const positive = new SshWriter().mpint(new Uint8Array([0x80, 0x01])).toBuffer()
    expect([...new SshReader(positive).string()]).toEqual([0x00, 0x80, 0x01])

    const plain = new SshWriter().mpint(new Uint8Array([0x7f, 0x01])).toBuffer()
    expect([...new SshReader(plain).string()]).toEqual([0x7f, 0x01])
  })

  it('strips leading zeros and encodes zero as an empty string', () => {
    const trimmed = new SshWriter().mpint(new Uint8Array([0x00, 0x00, 0x09])).toBuffer()
    expect([...new SshReader(trimmed).string()]).toEqual([0x09])

    const zero = new SshWriter().mpint(new Uint8Array([0x00, 0x00])).toBuffer()
    expect(new SshReader(zero).string().length).toBe(0)
  })

  it('reports truncated packets instead of reading past the end', () => {
    const reader = new SshReader(new Uint8Array([0, 0, 0, 8, 1, 2]))
    expect(() => reader.string()).toThrow(/truncated/)
  })

  it('compares in constant time, including length mismatches', () => {
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true)
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false)
    expect(timingSafeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false)
  })

  it('concatenates in order', () => {
    expect([...concat(new Uint8Array([1]), new Uint8Array([2, 3]), new Uint8Array())]).toEqual([1, 2, 3])
  })
})
