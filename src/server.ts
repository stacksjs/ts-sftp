/**
 * The server: a Bun TCP listener that hands each connection to the SSH
 * transport, and the default authenticator and file system that back it.
 */

import type { TCPSocketListener } from 'bun'
import type { HostKey, SshPublicKey } from './keys'
import type { SftpAuthContext, SftpFileSystem, SftpLogger, SftpServerOptions, SftpSessionContext, SftpUserConfig } from './types'
import { SshConnection } from './connection'
import { LocalFileSystem } from './filesystem/local'
import { SocketWriter } from './socket-writer'
import { generateHostKey, loadHostKey, parsePublicKey } from './keys'
import { timingSafeEqual } from './wire'

const DEFAULT_PORT = 2222
const DEFAULT_MAX_CONNECTIONS = 100

/** Per-socket state: the SSH connection driving it. */
interface SocketData {
  connection?: SshConnection
  writer?: SocketWriter
}

/** A running server. */
export interface RunningSftpServer {
  port: number
  hostname: string
  /** Number of connections currently open. */
  connections: number
  stop: () => Promise<void>
}

function defaultLogger(): SftpLogger {
  return {
    warn: (message, details) => console.warn(`[ts-sftp] ${message}`, details ?? ''),
    error: (message, details) => console.error(`[ts-sftp] ${message}`, details ?? ''),
  }
}

function resolvePublicKeys(keys: (string | SshPublicKey)[] | undefined): SshPublicKey[] {
  if (!keys) return []
  return keys.flatMap((key) => {
    if (typeof key !== 'string') return [key]
    const parsed = parsePublicKey(key)
    return parsed ? [parsed] : []
  })
}

/**
 * The built-in authenticator: a user is accepted when the key that signed the
 * request is one of theirs, or when their configured password matches.
 *
 * A `publickey` context only reaches here after the signature has been
 * verified against a key listed for that user, so the presence of the key is
 * the proof.
 */
export function authenticateAgainstUsers(
  users: Record<string, SftpUserConfig> | undefined,
  context: SftpAuthContext,
): boolean {
  const user = users?.[context.username]
  if (!user) return false

  if (context.method === 'publickey') return context.publicKey !== undefined

  if (context.method === 'password' && user.password !== undefined && context.password !== undefined) {
    const encoder = new TextEncoder()
    return timingSafeEqual(encoder.encode(user.password), encoder.encode(context.password))
  }

  return false
}

/**
 * An SFTP server.
 *
 * Users are authenticated by public key (or password, if configured), then get
 * a file system rooted at their own directory.
 */
export class SftpServer {
  private readonly logger: SftpLogger
  private readonly hostKey: HostKey
  private readonly userKeys = new Map<string, SshPublicKey[]>()
  private server?: TCPSocketListener<SocketData>
  private open = 0

  constructor(private readonly options: SftpServerOptions = {}) {
    this.logger = options.logger ?? defaultLogger()

    const hostKeys = options.hostKeys ?? []
    if (hostKeys.length > 1)
      this.logger.warn?.('multiple host keys given; using the first — only Ed25519 host keys are supported')

    const first = hostKeys[0]
    this.hostKey = first === undefined ? generateHostKey() : typeof first === 'string' ? loadHostKey(first) : first
    if (first === undefined)
      this.logger.warn?.('no host key configured — generated an ephemeral one, so clients will see a new fingerprint after every restart')

    for (const [username, user] of Object.entries(options.users ?? {}))
      this.userKeys.set(username, resolvePublicKeys(user.publicKeys))
  }

  /** The server's host key fingerprint, for pinning or `known_hosts` checks. */
  get hostKeyBlob(): Uint8Array {
    return this.hostKey.blob
  }

  private authorizedKeysFor(username: string): SshPublicKey[] {
    return this.userKeys.get(username) ?? []
  }

  private async authenticate(context: SftpAuthContext): Promise<boolean> {
    if (this.options.authenticate) return await this.options.authenticate(context)
    return authenticateAgainstUsers(this.options.users, context)
  }

  private async createFileSystem(context: SftpSessionContext): Promise<SftpFileSystem> {
    if (this.options.createFileSystem) return await this.options.createFileSystem(context)

    const user = this.options.users?.[context.username]
    const root = user?.root ?? this.options.root ?? process.cwd()
    return new LocalFileSystem(root, { readOnly: this.options.readOnly || user?.readOnly })
  }

  /** Start listening. Resolves once the socket is bound. */
  listen(): RunningSftpServer {
    const port = this.options.port ?? DEFAULT_PORT
    const hostname = this.options.hostname ?? '0.0.0.0'
    const maxConnections = this.options.maxConnections ?? DEFAULT_MAX_CONNECTIONS

    const server: TCPSocketListener<SocketData> = Bun.listen<SocketData>({
      hostname,
      port,
      socket: {
        open: (socket) => {
          if (this.open >= maxConnections) {
            this.logger.warn?.('refused a connection: too many open sessions', { maxConnections })
            socket.end()
            return
          }
          this.open++

          // A socket write can be short; the writer holds the remainder until
          // the socket drains instead of dropping it. A peer that stops reading
          // altogether is hung up on rather than buffered indefinitely.
          const writer = new SocketWriter(socket, {
            maxBacklog: this.options.maxWriteBacklog,
            onOverflow: () => {
              this.logger.warn?.('closing a connection that stopped reading', {
                remoteAddress: socket.remoteAddress,
              })
              socket.end()
            },
          })

          socket.data = {
            writer,
            connection: new SshConnection({
              hostKey: this.hostKey,
              remoteAddress: socket.remoteAddress,
              logger: this.logger,
              authTimeoutMs: this.options.authTimeoutMs,
              maxAuthAttempts: this.options.maxAuthAttempts,
              write: (data) => {
                writer.write(data)
              },
              close: () => {
                socket.end()
              },
              authenticate: (context) => this.authenticate(context),
              authorizedKeysFor: (username) => this.authorizedKeysFor(username),
              createFileSystem: (context) => this.createFileSystem(context),
            }),
          }
        },
        data: (socket, data) => {
          socket.data?.connection?.push(new Uint8Array(data))
        },
        drain: (socket) => {
          socket.data?.writer?.drain()
        },
        close: (socket) => {
          this.open = Math.max(0, this.open - 1)
          void socket.data?.connection?.dispose()
        },
        error: (socket, error) => {
          this.logger.error?.('socket error', { error: error.message })
          void socket.data?.connection?.dispose()
        },
      },
    })

    this.server = server
    this.logger.info?.('listening', { hostname, port: server.port })

    const self = this
    return {
      port: server.port,
      hostname,
      get connections() {
        return self.open
      },
      stop: () => self.stop(),
    }
  }

  /** Stop listening. Open connections are closed. */
  async stop(): Promise<void> {
    this.server?.stop(true)
    this.server = undefined
  }
}

/** Start a server in one call. */
export function createSftpServer(options: SftpServerOptions = {}): { server: SftpServer; running: RunningSftpServer } {
  const server = new SftpServer(options)
  return { server, running: server.listen() }
}
