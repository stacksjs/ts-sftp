#!/usr/bin/env bun
/** `ts-sftp` — serve a directory over SFTP, or generate a host key. */

import type { SftpServerOptions, SftpUserConfig } from '../src/types'
import { CLI } from '@stacksjs/clapp'
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { version } from '../package.json'
import { loadConfig } from '../src/config'
import { generateHostKeyFiles } from '../src/keys'
import { SftpServer } from '../src/server'

interface ServeOptions {
  config?: string
  port?: number | string
  host?: string
  root?: string
  hostKey?: string
  user?: string | string[]
  readOnly?: boolean
  verbose?: boolean
}

interface KeygenOptions {
  out?: string
  comment?: string
}

/** Read the `<name>:<authorized_keys path>` pairs given on the command line. */
async function usersFromFlags(user: string | string[] | undefined): Promise<Record<string, SftpUserConfig>> {
  const entries = user === undefined ? [] : Array.isArray(user) ? user : [user]
  const users: Record<string, SftpUserConfig> = {}

  for (const entry of entries) {
    const separator = entry.indexOf(':')
    if (separator === -1) throw new Error(`--user expects <name>:<authorized_keys path>, got "${entry}"`)

    const username = entry.slice(0, separator)
    const text = await readFile(resolve(entry.slice(separator + 1)), 'utf8')
    users[username] = { publicKeys: text.split('\n').filter((line) => line.trim() && !line.startsWith('#')) }
  }

  return users
}

const cli = new CLI('ts-sftp')

cli
  .command('serve', 'Serve a directory over SFTP')
  .option('--config <path>', 'Config file (default: sftp.config.ts, if present)')
  .option('--port <port>', 'Port to listen on', { default: undefined })
  .option('--host <address>', 'Address to bind')
  .option('--root <dir>', 'Directory to serve')
  .option('--host-key <path>', 'Host key file. Generated in memory when omitted')
  .option('--user <name:keys>', 'Grant a user access using an authorized_keys file. Repeatable')
  .option('--read-only', 'Reject every write')
  .option('--verbose', 'Log each connection and request')
  .example('ts-sftp serve --root ./uploads --host-key ./host_key --user deploy:./deploy.pub')
  .action(async (options: ServeOptions) => {
    const fileConfig = await loadConfig(options.config)
    const cliUsers = await usersFromFlags(options.user)

    const hostKeys = options.hostKey
      ? [await readFile(resolve(options.hostKey), 'utf8')]
      : fileConfig.hostKeys

    const log = (message: string, details?: Record<string, unknown>): void => {
      console.log(`[ts-sftp] ${message}`, details ?? '')
    }

    const serverOptions: SftpServerOptions = {
      ...fileConfig,
      hostKeys,
      port: options.port === undefined ? fileConfig.port : Number(options.port),
      hostname: options.host ?? fileConfig.hostname,
      root: options.root ? resolve(options.root) : fileConfig.root,
      readOnly: options.readOnly === true || fileConfig.readOnly,
      users: { ...fileConfig.users, ...cliUsers },
      logger: {
        info: log,
        warn: (message, details) => console.warn(`[ts-sftp] ${message}`, details ?? ''),
        error: (message, details) => console.error(`[ts-sftp] ${message}`, details ?? ''),
        debug: options.verbose === true ? log : undefined,
      },
    }

    if (Object.keys(serverOptions.users ?? {}).length === 0) {
      console.error('ts-sftp: no users configured — add --user <name>:<authorized_keys path> or a config file')
      process.exitCode = 1
      return
    }

    const server = new SftpServer(serverOptions)
    const running = server.listen()

    console.log(`ts-sftp listening on ${running.hostname}:${running.port}, serving ${serverOptions.root}`)
    console.log(
      `users: ${Object.keys(serverOptions.users ?? {}).join(', ')}${serverOptions.readOnly ? ' (read-only)' : ''}`,
    )

    const shutdown = (): void => {
      console.log('\nts-sftp shutting down')
      void server.stop().then(() => process.exit(0))
    }
    process.on('SIGINT', shutdown)
    process.on('SIGTERM', shutdown)

    // Hold the process open for as long as the listener is.
    await new Promise(() => {})
  })

cli
  .command('keygen', 'Generate an Ed25519 host key')
  .option('--out <path>', 'Where to write the key', { default: './ts-sftp_host_ed25519' })
  .option('--comment <text>', 'Comment stored in the key', { default: 'ts-sftp' })
  .example('ts-sftp keygen --out /etc/ts-sftp/host_key')
  .action(async (options: KeygenOptions) => {
    const out = resolve(options.out ?? './ts-sftp_host_ed25519')
    const { privateKey, publicKey } = generateHostKeyFiles(options.comment ?? 'ts-sftp')

    await mkdir(dirname(out), { recursive: true })
    await writeFile(out, privateKey, { mode: 0o600 })
    // The mode above only applies when the file is created; enforce it either way.
    await chmod(out, 0o600)
    await writeFile(`${out}.pub`, publicKey, { mode: 0o644 })

    console.log(`Wrote ${out} and ${out}.pub`)
  })

cli.version(version)
cli.help()
cli.parse()
