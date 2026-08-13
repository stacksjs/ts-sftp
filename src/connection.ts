/**
 * One client connection: version exchange, key exchange, authentication, and
 * the single `sftp` subsystem channel that follows.
 */

import type { HostKey, SshPublicKey } from './keys'
import type { SftpAuthContext, SftpFileSystem, SftpLogger, SftpSessionContext } from './types'
import { randomBytes } from 'node:crypto'
import { SSH_DISCONNECT, SSH_IDENT, SSH_MSG, SSH_OPEN } from './constants'
import {
  CIPHERS,
  COMPRESSION,
  computeExchangeHash,
  deriveSessionKeys,
  generateEphemeralKeyPair,
  HOST_KEY_ALGORITHMS,
  KEX_ALGORITHMS,
  MACS,
  negotiate,
  signExchangeHash,
} from './kex'
import { signatureAlgorithmsFor, verifySignature } from './keys'
import { PacketCodec } from './packet'
import { SftpSession } from './sftp-session'
import { concat, SshReader, SshWriter } from './wire'

/** Advertised alongside our KEX algorithms to enable OpenSSH's strict KEX. */
const STRICT_KEX_SERVER = 'kex-strict-s-v00@openssh.com'
const STRICT_KEX_CLIENT = 'kex-strict-c-v00@openssh.com'

const DEFAULT_MAX_AUTH_ATTEMPTS = 6
const MAX_IDENT_LENGTH = 255
const WINDOW_SIZE = 2 * 1024 * 1024
const MAX_CHANNEL_PACKET = 32 * 1024

/** What the connection needs from its host to do its job. */
export interface ConnectionOptions {
  hostKey: HostKey
  write: (data: Uint8Array) => void
  close: () => void
  authenticate: (context: SftpAuthContext) => boolean | Promise<boolean>
  /** Which key algorithms may be offered for a user, before any signature check. */
  authorizedKeysFor: (username: string) => SshPublicKey[] | Promise<SshPublicKey[]>
  createFileSystem: (context: SftpSessionContext) => SftpFileSystem | Promise<SftpFileSystem>
  logger?: SftpLogger
  remoteAddress?: string
  authTimeoutMs?: number
  maxAuthAttempts?: number
}

interface ChannelState {
  localId: number
  remoteId: number
  remoteWindow: number
  remoteMaxPacket: number
  localWindow: number
  session?: SftpSession
  outgoing: Uint8Array[]
  closed: boolean
}

export class SshConnection {
  private readonly codec = new PacketCodec()
  private readonly logger: SftpLogger
  private buffer: Uint8Array = new Uint8Array(0)
  private identReceived = false
  private clientVersion = ''
  private readonly serverVersion = SSH_IDENT

  private clientKexInit?: Uint8Array
  private serverKexInit?: Uint8Array
  private sessionId?: Uint8Array
  private strictKex = false
  private pendingNewKeys?: { key: Uint8Array; iv: Uint8Array }

  private authenticated = false
  private username?: string
  private authAttempts = 0
  private authTimer?: ReturnType<typeof setTimeout>

  private channel?: ChannelState
  /** Serializes packet handling so async work cannot interleave mid-stream. */
  private queue: Promise<void> = Promise.resolve()
  private closed = false

  constructor(private readonly options: ConnectionOptions) {
    this.logger = options.logger ?? {}
    this.options.write(new TextEncoder().encode(`${this.serverVersion}\r\n`))

    const timeout = options.authTimeoutMs ?? 30_000
    if (timeout > 0) {
      this.authTimer = setTimeout(() => {
        if (!this.authenticated) {
          this.logger.warn?.('authentication timed out', { remoteAddress: options.remoteAddress })
          this.disconnect(SSH_DISCONNECT.AUTH_CANCELLED_BY_USER, 'authentication timed out')
        }
      }, timeout)
    }
  }

  /** Feed bytes from the socket. */
  push(data: Uint8Array): void {
    this.queue = this.queue.then(() => this.consume(data)).catch((error) => {
      this.logger.error?.('connection failed', {
        remoteAddress: this.options.remoteAddress,
        error: error instanceof Error ? error.message : String(error),
      })
      this.disconnect(SSH_DISCONNECT.PROTOCOL_ERROR, error instanceof Error ? error.message : 'protocol error')
    })
  }

  /** Release the session and stop the auth timer. */
  async dispose(): Promise<void> {
    this.closed = true
    if (this.authTimer) clearTimeout(this.authTimer)
    await this.channel?.session?.close()
  }

  private async consume(data: Uint8Array): Promise<void> {
    if (this.closed) return
    this.buffer = this.buffer.length === 0 ? data : concat(this.buffer, data)

    if (!this.identReceived && !this.readIdentification()) return

    for (;;) {
      const packet = this.codec.decode(this.buffer)
      if (!packet) return
      this.buffer = this.buffer.subarray(packet.consumed)
      await this.handlePacket(packet.payload)
      if (this.closed) return
    }
  }

  /**
   * Read the client's identification line. Anything before it is a banner the
   * client is allowed to send, and is discarded.
   */
  private readIdentification(): boolean {
    for (;;) {
      const text = new TextDecoder().decode(this.buffer)
      const end = text.indexOf('\r\n')
      if (end === -1) {
        if (this.buffer.length > MAX_IDENT_LENGTH * 4) throw new Error('ssh: identification string too long')
        return false
      }

      const line = text.slice(0, end)
      this.buffer = this.buffer.subarray(end + 2)

      if (line.startsWith('SSH-')) {
        if (!line.startsWith('SSH-2.0-')) throw new Error(`ssh: unsupported protocol version: ${line}`)
        this.clientVersion = line
        this.identReceived = true
        this.sendKexInit()
        return true
      }
    }
  }

  private send(payload: Uint8Array): void {
    if (this.closed) return
    this.options.write(this.codec.encode(payload))
  }

  private disconnect(reason: number, description: string): void {
    if (this.closed) return
    try {
      this.send(new SshWriter().byte(SSH_MSG.DISCONNECT).uint32(reason).string(description).string('').toBuffer())
    }
    catch {
      // The socket may already be gone; closing below is what matters.
    }
    this.closed = true
    this.options.close()
  }

  private sendKexInit(): void {
    const cookie = new Uint8Array(randomBytes(16))
    const payload = new SshWriter()
      .byte(SSH_MSG.KEXINIT)
      .raw(cookie)
      .nameList([...KEX_ALGORITHMS, STRICT_KEX_SERVER])
      .nameList(HOST_KEY_ALGORITHMS)
      .nameList(CIPHERS)
      .nameList(CIPHERS)
      .nameList(MACS)
      .nameList(MACS)
      .nameList(COMPRESSION)
      .nameList(COMPRESSION)
      .nameList([])
      .nameList([])
      .boolean(false)
      .uint32(0)
      .toBuffer()

    this.serverKexInit = payload
    this.send(payload)
  }

  private async handlePacket(payload: Uint8Array): Promise<void> {
    if (payload.length === 0) return
    const type = payload[0]!

    switch (type) {
      case SSH_MSG.DISCONNECT:
        this.closed = true
        this.options.close()
        return

      case SSH_MSG.IGNORE:
      case SSH_MSG.DEBUG:
      case SSH_MSG.UNIMPLEMENTED:
        return

      case SSH_MSG.KEXINIT:
        this.handleKexInit(payload)
        return

      case SSH_MSG.KEX_ECDH_INIT:
        this.handleKexEcdhInit(payload)
        return

      case SSH_MSG.NEWKEYS:
        if (!this.pendingNewKeys) throw new Error('ssh: unexpected NEWKEYS')
        this.codec.setIncomingKeys(this.pendingNewKeys)
        this.pendingNewKeys = undefined
        if (this.strictKex) this.codec.receiveSequence = 0
        return

      case SSH_MSG.SERVICE_REQUEST: {
        const service = new SshReader(payload, 1).utf8()
        if (service !== 'ssh-userauth') {
          this.disconnect(SSH_DISCONNECT.SERVICE_NOT_AVAILABLE, `service not available: ${service}`)
          return
        }
        this.send(new SshWriter().byte(SSH_MSG.SERVICE_ACCEPT).string(service).toBuffer())
        return
      }

      case SSH_MSG.USERAUTH_REQUEST:
        await this.handleAuthRequest(payload)
        return

      case SSH_MSG.CHANNEL_OPEN:
        this.handleChannelOpen(payload)
        return

      case SSH_MSG.CHANNEL_REQUEST:
        await this.handleChannelRequest(payload)
        return

      case SSH_MSG.CHANNEL_DATA:
        await this.handleChannelData(payload)
        return

      case SSH_MSG.CHANNEL_WINDOW_ADJUST: {
        const reader = new SshReader(payload, 1)
        reader.uint32()
        const bytes = reader.uint32()
        if (this.channel) {
          this.channel.remoteWindow += bytes
          this.flushChannel()
        }
        return
      }

      case SSH_MSG.CHANNEL_EOF:
        // The client is done sending. Finish the exchange from our side so it
        // can tear the channel down instead of waiting on us.
        await this.closeChannel()
        return

      case SSH_MSG.CHANNEL_CLOSE: {
        await this.closeChannel()
        this.closed = true
        this.options.close()
        return
      }

      case SSH_MSG.GLOBAL_REQUEST: {
        const reader = new SshReader(payload, 1)
        reader.utf8()
        if (reader.boolean()) this.send(new SshWriter().byte(SSH_MSG.REQUEST_FAILURE).toBuffer())
        return
      }

      default:
        this.send(new SshWriter().byte(SSH_MSG.UNIMPLEMENTED).uint32(this.codec.receiveSequence - 1).toBuffer())
    }
  }

  private handleKexInit(payload: Uint8Array): void {
    const reader = new SshReader(payload, 1)
    reader.raw(16) // cookie

    const kexAlgorithms = reader.nameList()
    const hostKeyAlgorithms = reader.nameList()
    const ciphersClientToServer = reader.nameList()
    const ciphersServerToClient = reader.nameList()

    this.clientKexInit = payload
    // Strict KEX is only in force when both sides asked for it.
    this.strictKex = kexAlgorithms.includes(STRICT_KEX_CLIENT)

    // A rekey starts with the client's KEXINIT; answer with a fresh one of ours.
    if (this.sessionId) this.sendKexInit()

    negotiate(kexAlgorithms, KEX_ALGORITHMS, 'key exchange algorithm')
    negotiate(hostKeyAlgorithms, HOST_KEY_ALGORITHMS, 'host key algorithm')
    negotiate(ciphersClientToServer, CIPHERS, 'client-to-server cipher')
    negotiate(ciphersServerToClient, CIPHERS, 'server-to-client cipher')
  }

  private handleKexEcdhInit(payload: Uint8Array): void {
    if (!this.clientKexInit || !this.serverKexInit) throw new Error('ssh: key exchange started before KEXINIT')

    const clientPublicKey = new SshReader(payload, 1).string()
    const ephemeral = generateEphemeralKeyPair()
    const sharedSecret = ephemeral.derive(clientPublicKey)

    const exchangeHash = computeExchangeHash({
      clientVersion: this.clientVersion,
      serverVersion: this.serverVersion,
      clientKexInit: this.clientKexInit,
      serverKexInit: this.serverKexInit,
      hostKeyBlob: this.options.hostKey.blob,
      clientPublicKey,
      serverPublicKey: ephemeral.publicKey,
      sharedSecret,
    })

    // The first exchange hash becomes the session ID for the connection's life.
    this.sessionId ??= exchangeHash

    this.send(
      new SshWriter()
        .byte(SSH_MSG.KEX_ECDH_REPLY)
        .string(this.options.hostKey.blob)
        .string(ephemeral.publicKey)
        .string(signExchangeHash(this.options.hostKey, exchangeHash))
        .toBuffer(),
    )

    const keys = deriveSessionKeys(sharedSecret, exchangeHash, this.sessionId)
    this.send(new SshWriter().byte(SSH_MSG.NEWKEYS).toBuffer())

    // Ours takes effect immediately after NEWKEYS goes out; the client's when
    // its own NEWKEYS arrives.
    this.codec.setOutgoingKeys(keys.serverToClient)
    if (this.strictKex) this.codec.sendSequence = 0
    this.pendingNewKeys = keys.clientToServer
  }

  private authFailure(): void {
    this.authAttempts++
    this.send(
      new SshWriter().byte(SSH_MSG.USERAUTH_FAILURE).nameList(['publickey', 'password']).boolean(false).toBuffer(),
    )
    if (this.authAttempts >= (this.options.maxAuthAttempts ?? DEFAULT_MAX_AUTH_ATTEMPTS))
      this.disconnect(SSH_DISCONNECT.NO_MORE_AUTH_METHODS_AVAILABLE, 'too many authentication attempts')
  }

  private async handleAuthRequest(payload: Uint8Array): Promise<void> {
    if (this.authenticated) return

    const reader = new SshReader(payload, 1)
    const username = reader.utf8()
    const service = reader.utf8()
    const method = reader.utf8()

    if (service !== 'ssh-connection') {
      this.authFailure()
      return
    }

    if (method === 'password') {
      reader.boolean() // password change request
      const password = reader.utf8()
      await this.finishAuth(username, {
        username,
        method: 'password',
        password,
        remoteAddress: this.options.remoteAddress,
      })
      return
    }

    if (method !== 'publickey') {
      this.authFailure()
      return
    }

    const hasSignature = reader.boolean()
    const algorithm = reader.utf8()
    const blob = reader.string()
    const authorized = await this.options.authorizedKeysFor(username)
    const key = authorized.find(
      (candidate) =>
        candidate.blob.length === blob.length
        && candidate.blob.every((byte, index) => byte === blob[index])
        && signatureAlgorithmsFor(candidate.algorithm).includes(algorithm),
    )

    if (!key) {
      this.authFailure()
      return
    }

    if (!hasSignature) {
      // The client is asking whether this key is worth signing with.
      this.send(new SshWriter().byte(SSH_MSG.USERAUTH_PK_OK).string(algorithm).string(blob).toBuffer())
      return
    }

    const signature = reader.string()
    const signed = new SshWriter()
      .string(this.sessionId!)
      .byte(SSH_MSG.USERAUTH_REQUEST)
      .string(username)
      .string(service)
      .string('publickey')
      .boolean(true)
      .string(algorithm)
      .string(blob)
      .toBuffer()

    if (!verifySignature(key, algorithm, signed, signature)) {
      this.logger.warn?.('rejected a bad signature', { username, remoteAddress: this.options.remoteAddress })
      this.authFailure()
      return
    }

    await this.finishAuth(username, {
      username,
      method: 'publickey',
      publicKey: key,
      remoteAddress: this.options.remoteAddress,
    })
  }

  private async finishAuth(username: string, context: SftpAuthContext): Promise<void> {
    let accepted = false
    try {
      accepted = await this.options.authenticate(context)
    }
    catch (error) {
      this.logger.error?.('authenticator threw', {
        username,
        error: error instanceof Error ? error.message : String(error),
      })
    }

    if (!accepted) {
      this.logger.warn?.('authentication failed', {
        username,
        method: context.method,
        remoteAddress: this.options.remoteAddress,
      })
      this.authFailure()
      return
    }

    this.authenticated = true
    this.username = username
    if (this.authTimer) clearTimeout(this.authTimer)
    this.logger.info?.('authenticated', {
      username,
      method: context.method,
      remoteAddress: this.options.remoteAddress,
    })
    this.send(new SshWriter().byte(SSH_MSG.USERAUTH_SUCCESS).toBuffer())
  }

  private handleChannelOpen(payload: Uint8Array): void {
    const reader = new SshReader(payload, 1)
    const type = reader.utf8()
    const remoteId = reader.uint32()
    const remoteWindow = reader.uint32()
    const remoteMaxPacket = reader.uint32()

    const refuse = (reason: number, description: string): void => {
      this.send(
        new SshWriter()
          .byte(SSH_MSG.CHANNEL_OPEN_FAILURE)
          .uint32(remoteId)
          .uint32(reason)
          .string(description)
          .string('')
          .toBuffer(),
      )
    }

    if (!this.authenticated) {
      refuse(SSH_OPEN.ADMINISTRATIVELY_PROHIBITED, 'not authenticated')
      return
    }
    if (type !== 'session') {
      refuse(SSH_OPEN.UNKNOWN_CHANNEL_TYPE, `unsupported channel type: ${type}`)
      return
    }
    if (this.channel) {
      refuse(SSH_OPEN.RESOURCE_SHORTAGE, 'only one session channel is supported')
      return
    }

    this.channel = {
      localId: 0,
      remoteId,
      remoteWindow,
      remoteMaxPacket: Math.min(remoteMaxPacket, MAX_CHANNEL_PACKET),
      localWindow: WINDOW_SIZE,
      outgoing: [],
      closed: false,
    }

    this.send(
      new SshWriter()
        .byte(SSH_MSG.CHANNEL_OPEN_CONFIRMATION)
        .uint32(remoteId)
        .uint32(0)
        .uint32(WINDOW_SIZE)
        .uint32(MAX_CHANNEL_PACKET)
        .toBuffer(),
    )
  }

  private async handleChannelRequest(payload: Uint8Array): Promise<void> {
    const reader = new SshReader(payload, 1)
    reader.uint32() // recipient channel
    const request = reader.utf8()
    const wantReply = reader.boolean()

    const channel = this.channel
    if (!channel) return

    const succeed = (ok: boolean): void => {
      if (wantReply)
        this.send(
          new SshWriter().byte(ok ? SSH_MSG.CHANNEL_SUCCESS : SSH_MSG.CHANNEL_FAILURE).uint32(channel.remoteId)
            .toBuffer(),
        )
    }

    if (request !== 'subsystem') {
      // `exec`, `shell`, and `pty-req` are deliberately unsupported: this is a
      // file transfer server, not a shell host.
      succeed(false)
      return
    }

    const subsystem = reader.utf8()
    if (subsystem !== 'sftp') {
      succeed(false)
      return
    }

    const fs = await this.options.createFileSystem({
      username: this.username!,
      remoteAddress: this.options.remoteAddress,
    })

    channel.session = new SftpSession(fs, (data) => this.writeChannel(data), this.logger)
    succeed(true)
  }

  private async handleChannelData(payload: Uint8Array): Promise<void> {
    const reader = new SshReader(payload, 1)
    reader.uint32() // recipient channel
    const data = reader.string()

    const channel = this.channel
    if (!channel?.session) return

    channel.localWindow -= data.length
    if (channel.localWindow < WINDOW_SIZE / 2) {
      const adjust = WINDOW_SIZE - channel.localWindow
      channel.localWindow = WINDOW_SIZE
      this.send(
        new SshWriter().byte(SSH_MSG.CHANNEL_WINDOW_ADJUST).uint32(channel.remoteId).uint32(adjust).toBuffer(),
      )
    }

    await channel.session.receive(data)
  }

  /**
   * Finish the session channel: report the exit status the client waits for,
   * then send EOF and close. Safe to call more than once.
   */
  private async closeChannel(): Promise<void> {
    const channel = this.channel
    if (!channel || channel.closed) return
    channel.closed = true

    this.flushChannel()
    await channel.session?.close()

    this.send(
      new SshWriter()
        .byte(SSH_MSG.CHANNEL_REQUEST)
        .uint32(channel.remoteId)
        .string('exit-status')
        .boolean(false)
        .uint32(0)
        .toBuffer(),
    )
    this.send(new SshWriter().byte(SSH_MSG.CHANNEL_EOF).uint32(channel.remoteId).toBuffer())
    this.send(new SshWriter().byte(SSH_MSG.CHANNEL_CLOSE).uint32(channel.remoteId).toBuffer())
  }

  /** Queue channel data, respecting the peer's window and packet size. */
  private writeChannel(data: Uint8Array): void {
    const channel = this.channel
    if (!channel || channel.closed) return
    channel.outgoing.push(data)
    this.flushChannel()
  }

  private flushChannel(): void {
    const channel = this.channel
    if (!channel || channel.closed) return

    while (channel.outgoing.length > 0) {
      const next = channel.outgoing[0]!
      const size = Math.min(next.length, channel.remoteWindow, channel.remoteMaxPacket)
      if (size <= 0) return

      const chunk = next.subarray(0, size)
      if (size === next.length) channel.outgoing.shift()
      else channel.outgoing[0] = next.subarray(size)

      channel.remoteWindow -= size
      this.send(new SshWriter().byte(SSH_MSG.CHANNEL_DATA).uint32(channel.remoteId).string(chunk).toBuffer())
    }
  }
}
