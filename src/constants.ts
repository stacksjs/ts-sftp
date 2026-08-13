/**
 * Protocol constants for the SSH transport (RFC 4250-4254) and the SFTP
 * subsystem (draft-ietf-secsh-filexfer-02, the version 3 every client speaks).
 */

/** SSH transport, authentication, and connection message numbers. */
export const SSH_MSG = {
  DISCONNECT: 1,
  IGNORE: 2,
  UNIMPLEMENTED: 3,
  DEBUG: 4,
  SERVICE_REQUEST: 5,
  SERVICE_ACCEPT: 6,
  EXT_INFO: 7,
  KEXINIT: 20,
  NEWKEYS: 21,
  /** Shares its number with other KEX methods; ours is always ECDH. */
  KEX_ECDH_INIT: 30,
  KEX_ECDH_REPLY: 31,
  USERAUTH_REQUEST: 50,
  USERAUTH_FAILURE: 51,
  USERAUTH_SUCCESS: 52,
  USERAUTH_BANNER: 53,
  /** Method-specific, 60 for publickey is SSH_MSG_USERAUTH_PK_OK. */
  USERAUTH_PK_OK: 60,
  GLOBAL_REQUEST: 80,
  REQUEST_SUCCESS: 81,
  REQUEST_FAILURE: 82,
  CHANNEL_OPEN: 90,
  CHANNEL_OPEN_CONFIRMATION: 91,
  CHANNEL_OPEN_FAILURE: 92,
  CHANNEL_WINDOW_ADJUST: 93,
  CHANNEL_DATA: 94,
  CHANNEL_EXTENDED_DATA: 95,
  CHANNEL_EOF: 96,
  CHANNEL_CLOSE: 97,
  CHANNEL_REQUEST: 98,
  CHANNEL_SUCCESS: 99,
  CHANNEL_FAILURE: 100,
} as const

/** Disconnect reason codes (RFC 4253 §11.1). */
export const SSH_DISCONNECT = {
  PROTOCOL_ERROR: 2,
  KEY_EXCHANGE_FAILED: 3,
  MAC_ERROR: 5,
  SERVICE_NOT_AVAILABLE: 7,
  AUTH_CANCELLED_BY_USER: 13,
  NO_MORE_AUTH_METHODS_AVAILABLE: 14,
  BY_APPLICATION: 11,
} as const

/** Channel open failure reason codes (RFC 4254 §5.1). */
export const SSH_OPEN = {
  ADMINISTRATIVELY_PROHIBITED: 1,
  CONNECT_FAILED: 2,
  UNKNOWN_CHANNEL_TYPE: 3,
  RESOURCE_SHORTAGE: 4,
} as const

/** SFTP request and response packet types (version 3). */
export const SFTP = {
  INIT: 1,
  VERSION: 2,
  OPEN: 3,
  CLOSE: 4,
  READ: 5,
  WRITE: 6,
  LSTAT: 7,
  FSTAT: 8,
  SETSTAT: 9,
  FSETSTAT: 10,
  OPENDIR: 11,
  READDIR: 12,
  REMOVE: 13,
  MKDIR: 14,
  RMDIR: 15,
  REALPATH: 16,
  STAT: 17,
  RENAME: 18,
  READLINK: 19,
  SYMLINK: 20,
  STATUS: 101,
  HANDLE: 102,
  DATA: 103,
  NAME: 104,
  ATTRS: 105,
  EXTENDED: 200,
  EXTENDED_REPLY: 201,
} as const

/** SFTP status codes returned in SSH_FXP_STATUS. */
export const SFTP_STATUS = {
  OK: 0,
  EOF: 1,
  NO_SUCH_FILE: 2,
  PERMISSION_DENIED: 3,
  FAILURE: 4,
  BAD_MESSAGE: 5,
  NO_CONNECTION: 6,
  CONNECTION_LOST: 7,
  OP_UNSUPPORTED: 8,
} as const

/** Flags for SSH_FXP_OPEN. */
export const SFTP_OPEN = {
  READ: 0x00000001,
  WRITE: 0x00000002,
  APPEND: 0x00000004,
  CREAT: 0x00000008,
  TRUNC: 0x00000010,
  EXCL: 0x00000020,
} as const

/** Which fields an SSH_FXP_ATTRS structure carries. */
export const SFTP_ATTR = {
  SIZE: 0x00000001,
  UIDGID: 0x00000002,
  PERMISSIONS: 0x00000004,
  ACMODTIME: 0x00000008,
  EXTENDED: 0x80000000,
} as const

/** The SFTP protocol version this server implements. */
export const SFTP_VERSION = 3

/** Identification string sent during version exchange. */
export const SSH_IDENT = 'SSH-2.0-ts-sftp'
