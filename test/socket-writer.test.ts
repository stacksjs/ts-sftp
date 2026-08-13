import type { WritableSocket } from '../src/socket-writer'
import { describe, expect, it } from 'bun:test'
import { SocketWriter } from '../src/socket-writer'
import { concat } from '../src/wire'

/** A socket that accepts a fixed number of bytes per write, like a full buffer. */
function socketAccepting(limit: number): WritableSocket & { received: () => Uint8Array; open: (bytes: number) => void } {
  let accepted: Uint8Array = new Uint8Array(0)
  let remaining = limit

  return {
    write: (data) => {
      const take = Math.max(0, Math.min(data.length, remaining))
      accepted = concat(accepted, data.subarray(0, take))
      remaining -= take
      return take
    },
    received: () => accepted,
    open: (bytes) => {
      remaining += bytes
    },
  }
}

describe('socket writer', () => {
  it('passes bytes straight through when the socket takes them', () => {
    const socket = socketAccepting(Number.MAX_SAFE_INTEGER)
    const writer = new SocketWriter(socket)

    writer.write(new Uint8Array([1, 2, 3]))
    expect([...socket.received()]).toEqual([1, 2, 3])
    expect(writer.backlog).toBe(0)
  })

  it('keeps the remainder of a short write', () => {
    const socket = socketAccepting(2)
    const writer = new SocketWriter(socket)

    writer.write(new Uint8Array([1, 2, 3, 4, 5]))
    expect([...socket.received()]).toEqual([1, 2])
    expect(writer.backlog).toBe(3)
    expect([...writer.peek()]).toEqual([3, 4, 5])
  })

  it('delivers the backlog in order once the socket drains', () => {
    const socket = socketAccepting(2)
    const writer = new SocketWriter(socket)

    writer.write(new Uint8Array([1, 2, 3]))
    writer.write(new Uint8Array([4, 5]))
    expect([...socket.received()]).toEqual([1, 2])

    socket.open(1)
    writer.drain()
    expect([...socket.received()]).toEqual([1, 2, 3])
    expect(writer.backlog).toBe(2)

    socket.open(10)
    writer.drain()
    expect([...socket.received()]).toEqual([1, 2, 3, 4, 5])
    expect(writer.backlog).toBe(0)
  })

  it('queues behind an existing backlog rather than jumping ahead of it', () => {
    const socket = socketAccepting(0)
    const writer = new SocketWriter(socket)

    writer.write(new Uint8Array([1, 2]))
    writer.write(new Uint8Array([3, 4]))
    expect(socket.received()).toHaveLength(0)

    socket.open(100)
    writer.drain()
    expect([...socket.received()]).toEqual([1, 2, 3, 4])
  })

  it('handles a socket that takes nothing at all', () => {
    const socket = socketAccepting(0)
    const writer = new SocketWriter(socket)

    writer.write(new Uint8Array([9]))
    writer.drain()
    expect(writer.backlog).toBe(1)

    socket.open(1)
    writer.drain()
    expect([...socket.received()]).toEqual([9])
  })

  it('ignores empty writes', () => {
    const socket = socketAccepting(4)
    const writer = new SocketWriter(socket)

    writer.write(new Uint8Array(0))
    expect(writer.backlog).toBe(0)
    expect(socket.received()).toHaveLength(0)
  })

  it('reassembles a stream split across many short writes', () => {
    const socket = socketAccepting(1)
    const writer = new SocketWriter(socket)

    const payload = new Uint8Array(64)
    crypto.getRandomValues(payload)
    for (let offset = 0; offset < payload.length; offset += 8) writer.write(payload.subarray(offset, offset + 8))

    // One byte at a time, exactly as a congested socket would.
    for (let i = 0; i < payload.length; i++) {
      socket.open(1)
      writer.drain()
    }

    expect([...socket.received()]).toEqual([...payload])
  })
})
