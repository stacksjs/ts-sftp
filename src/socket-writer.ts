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

/**
 * How much unsent data may pile up before the peer is treated as unable (or
 * unwilling) to read. A client that opens a large download and then stops
 * reading would otherwise hold the whole file in the server's memory.
 */
export const DEFAULT_MAX_BACKLOG: number = 16 * 1024 * 1024

export interface SocketWriterOptions {
  /** Backlog ceiling in bytes. @default 16 MiB */
  maxBacklog?: number
  /** Called once when the ceiling is passed, to hang up on the peer. */
  onOverflow?: () => void
}

export class SocketWriter {
  private pending: Uint8Array[] = []
  private queued = 0
  private overflowed = false
  private readonly maxBacklog: number

  constructor(
    private readonly socket: WritableSocket,
    private readonly options: SocketWriterOptions = {},
  ) {
    this.maxBacklog = options.maxBacklog ?? DEFAULT_MAX_BACKLOG
  }

  /** Whether the peer stopped reading and the connection was given up on. */
  get stalled(): boolean {
    return this.overflowed
  }

  /** Bytes still waiting for the socket to drain. */
  get backlog(): number {
    return this.queued
  }

  /** Queue bytes, sending as much as the socket will take right now. */
  write(data: Uint8Array): void {
    if (data.length === 0 || this.overflowed) return

    // Anything already queued must go first, or the stream reorders.
    if (this.pending.length > 0) {
      this.enqueue(data)
      return
    }

    const written = this.socket.write(data)
    if (written < data.length) this.enqueue(data.subarray(Math.max(0, written)))
  }

  /** Called when the socket reports room again. */
  drain(): void {
    while (this.pending.length > 0) {
      const next = this.pending[0]!
      const written = this.socket.write(next)

      if (written < next.length) {
        this.pending[0] = next.subarray(Math.max(0, written))
        this.queued -= Math.max(0, written)
        return
      }
      this.pending.shift()
      this.queued -= next.length
    }
  }

  private enqueue(data: Uint8Array): void {
    this.pending.push(data)
    this.queued += data.length
    if (this.queued <= this.maxBacklog) return

    // The peer has stopped reading. Holding more of the transfer in memory
    // only moves the failure from its socket to our heap.
    this.overflowed = true
    this.pending = []
    this.queued = 0
    this.options.onOverflow?.()
  }

  /** Everything still queued, for tests and diagnostics. */
  peek(): Uint8Array {
    return concat(...this.pending)
  }
}
