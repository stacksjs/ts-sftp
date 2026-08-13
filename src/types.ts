/** Public types for configuring and extending the server. */

import type { HostKey, SshPublicKey } from './keys'

/** File attributes as SFTP models them — every field optional. */
export interface SftpAttributes {
  size?: number
  uid?: number
  gid?: number
  /** POSIX mode bits, including the file type (e.g. `0o100644` for a file). */
  mode?: number
  /** Access time, in seconds since the epoch. */
  atime?: number
  /** Modification time, in seconds since the epoch. */
  mtime?: number
}

/** One entry in a directory listing. */
export interface SftpDirectoryEntry {
  filename: string
  /** `ls -l` style line. Generated from the attributes when omitted. */
  longname?: string
  attributes: SftpAttributes
}

/** How a file is being opened, translated from the SFTP open flags. */
export interface SftpOpenFlags {
  read: boolean
  write: boolean
  append: boolean
  create: boolean
  truncate: boolean
  /** Fail if the file already exists. */
  exclusive: boolean
}

/** An open file, as handed back by a file system implementation. */
export interface SftpFileHandle {
  readonly path: string
}

/** An open directory, as handed back by a file system implementation. */
export interface SftpDirectoryHandle {
  readonly path: string
}

/**
 * The storage behind a session. Paths are absolute within the session's own
 * namespace — `/` is the user's root, and implementations are responsible for
 * keeping requests inside it.
 */
export interface SftpFileSystem {
  open: (path: string, flags: SftpOpenFlags, attributes: SftpAttributes) => Promise<SftpFileHandle>
  /** Resolves to undefined at end of file. */
  read: (handle: SftpFileHandle, offset: number, length: number) => Promise<Uint8Array | undefined>
  write: (handle: SftpFileHandle, offset: number, data: Uint8Array) => Promise<void>
  close: (handle: SftpFileHandle | SftpDirectoryHandle) => Promise<void>
  fstat: (handle: SftpFileHandle) => Promise<SftpAttributes>
  fsetstat: (handle: SftpFileHandle, attributes: SftpAttributes) => Promise<void>
  opendir: (path: string) => Promise<SftpDirectoryHandle>
  /** Resolves to undefined once the listing is exhausted. */
  readdir: (handle: SftpDirectoryHandle) => Promise<SftpDirectoryEntry[] | undefined>
  stat: (path: string) => Promise<SftpAttributes>
  lstat: (path: string) => Promise<SftpAttributes>
  setstat: (path: string, attributes: SftpAttributes) => Promise<void>
  remove: (path: string) => Promise<void>
  mkdir: (path: string, attributes: SftpAttributes) => Promise<void>
  rmdir: (path: string) => Promise<void>
  realpath: (path: string) => Promise<string>
  rename: (from: string, to: string) => Promise<void>
  readlink?: (path: string) => Promise<string>
  symlink?: (target: string, path: string) => Promise<void>
}

/** Identity and storage for one authenticated session. */
export interface SftpSessionContext {
  username: string
  /** Remote address the client connected from. */
  remoteAddress?: string
}

/** A user the server accepts. */
export interface SftpUserConfig {
  /** `authorized_keys` lines, or already-parsed keys. */
  publicKeys?: (string | SshPublicKey)[]
  /**
   * Accepted password. Provided for closed environments that cannot distribute
   * keys — public keys are the default and the better choice.
   */
  password?: string
  /** Directory this user is rooted at. Defaults to the server root. */
  root?: string
  /** Reject every write operation for this user. */
  readOnly?: boolean
}

/** Everything an authentication attempt is judged on. */
export interface SftpAuthContext {
  username: string
  method: 'publickey' | 'password'
  /** Present for `publickey` attempts, once the signature has been verified. */
  publicKey?: SshPublicKey
  /** Present for `password` attempts. */
  password?: string
  remoteAddress?: string
}

/** Log sink. Defaults to writing warnings and errors to the console. */
export interface SftpLogger {
  debug?: (message: string, details?: Record<string, unknown>) => void
  info?: (message: string, details?: Record<string, unknown>) => void
  warn?: (message: string, details?: Record<string, unknown>) => void
  error?: (message: string, details?: Record<string, unknown>) => void
}

/** Server configuration. */
export interface SftpServerOptions {
  /** Port to listen on. Defaults to 2222. */
  port?: number
  /** Address to bind. Defaults to `0.0.0.0`. */
  hostname?: string
  /**
   * Host keys, as OpenSSH/PEM private key text or already-loaded keys. When
   * omitted an ephemeral key is generated, which changes the fingerprint on
   * every restart — fine for tests, not for anything a client trusts.
   */
  hostKeys?: (string | HostKey)[]
  /** Directory served to users that do not set their own root. */
  root?: string
  /** Users accepted by the built-in authenticator. */
  users?: Record<string, SftpUserConfig>
  /**
   * Custom authentication. Runs after signature verification, so a returned
   * `true` means the key or password is genuine as well as accepted.
   */
  authenticate?: (context: SftpAuthContext) => boolean | Promise<boolean>
  /** Reject every write operation, whichever user is connected. */
  readOnly?: boolean
  /** Build the file system for a session. Defaults to local disk under the root. */
  createFileSystem?: (context: SftpSessionContext) => SftpFileSystem | Promise<SftpFileSystem>
  logger?: SftpLogger
  /** Refuse new connections past this many concurrent sessions. Defaults to 100. */
  maxConnections?: number
  /** Drop a connection that has not authenticated within this many ms. Defaults to 30000. */
  authTimeoutMs?: number
  /**
   * Failed authentication attempts allowed before the connection is dropped.
   * Defaults to 6, matching sshd's `MaxAuthTries`. Clients that offer several
   * keys spend one attempt per key, so raise it for agents holding many.
   */
  maxAuthAttempts?: number
}
