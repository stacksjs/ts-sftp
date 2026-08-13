/**
 * Backpressure-aware writing.
 *
 * A TCP write can accept fewer bytes than it was given once the kernel buffer
 * fills, which on a real network happens as soon as a transfer outruns the
 * link. Dropping the remainder desynchronizes the SSH stream — the peer reads
 * a packet length that no longer matches the bytes that follow and closes the
 * connection. Everything queued here is delivered, in order, as the socket
 * drains.
 */

import { concat } from './wire'

/** The part of a socket this writer needs. */
export interface WritableSocket {
  write: (data: Uint8Array) => number
}

export class SocketWriter {
  private pending: Uint8Array[] = []

  constructor(private readonly socket: WritableSocket) {}

  /** Bytes still waiting for the socket to drain. */
  get backlog(): number {
    return this.pending.reduce((total, chunk) => total + chunk.length, 0)
  }

  /** Queue bytes, sending as much as the socket will take right now. */
  write(data: Uint8Array): void {
    if (data.length === 0) return

    // Anything already queued must go first, or the stream reorders.
    if (this.pending.length > 0) {
      this.pending.push(data)
      return
    }

    const written = this.socket.write(data)
    if (written < data.length) this.pending.push(data.subarray(Math.max(0, written)))
  }

  /** Called when the socket reports room again. */
  drain(): void {
    while (this.pending.length > 0) {
      const next = this.pending[0]!
      const written = this.socket.write(next)

      if (written < next.length) {
        this.pending[0] = next.subarray(Math.max(0, written))
        return
      }
      this.pending.shift()
    }
  }

  /** Everything still queued, for tests and diagnostics. */
  peek(): Uint8Array {
    return concat(...this.pending)
  }
}
