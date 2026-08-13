/** Errors that carry an SFTP status code back to the client. */

import { SFTP_STATUS } from './constants'

/** An operation that failed with a specific SFTP status. */
export class SftpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message)
    this.name = 'SftpError'
  }

  static noSuchFile(path: string): SftpError {
    return new SftpError(SFTP_STATUS.NO_SUCH_FILE, `no such file: ${path}`)
  }

  static permissionDenied(reason: string): SftpError {
    return new SftpError(SFTP_STATUS.PERMISSION_DENIED, reason)
  }

  static failure(reason: string): SftpError {
    return new SftpError(SFTP_STATUS.FAILURE, reason)
  }

  static unsupported(operation: string): SftpError {
    return new SftpError(SFTP_STATUS.OP_UNSUPPORTED, `unsupported operation: ${operation}`)
  }
}

/** Map a Node file system error code onto the closest SFTP status. */
export function statusForSystemError(error: unknown): number {
  const code = (error as { code?: string } | undefined)?.code

  switch (code) {
    case 'ENOENT':
    case 'ENOTDIR':
      return SFTP_STATUS.NO_SUCH_FILE
    case 'EACCES':
    case 'EPERM':
    case 'EROFS':
      return SFTP_STATUS.PERMISSION_DENIED
    default:
      return SFTP_STATUS.FAILURE
  }
}

/** The status an error should be reported with. */
export function statusForError(error: unknown): number {
  return error instanceof SftpError ? error.status : statusForSystemError(error)
}
