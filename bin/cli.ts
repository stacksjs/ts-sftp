#!/usr/bin/env bun
/**
 * `ts-sftp` — serve a directory over SFTP, or generate a host key.
 *
 * Argument parsing is hand-rolled to keep the package dependency-free.
 */

import type { SftpServerOptions, SftpUserConfig } from '../src/types'
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { version } from '../package.json'
import { loadConfig } from '../src/config'
import { generateHostKeyFiles } from '../src/keys'
import { SftpServer } from '../src/server'

type FlagValue = string | boolean | string[]

interface ParsedArgs {
  command: string
  flags: Map<string, FlagValue>
  positional: string[]
}

/** Repeating a flag (`--user a --user b`) collects its values into an array. */
function addFlag(flags: Map<string, FlagValue>, name: string, value: string | boolean): void {
  const existing = flags.get(name)
  if (existing === undefined || typeof value === 'boolean') {
    flags.set(name, value)
    return
  }
  flags.set(name, Array.isArray(existing) ? [...existing, value] : [String(existing), value])
}

function parseArgs(argv: string[]): ParsedArgs {
  const flags = new Map<string, FlagValue>()
  const positional: string[] = []
  let command = ''

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!

    if (arg.startsWith('--')) {
      const [name, inline] = arg.slice(2).split('=', 2)
      const next = argv[i + 1]
      if (inline !== undefined) addFlag(flags, name!, inline)
      else if (next !== undefined && !next.startsWith('-')) {
        addFlag(flags, name!, next)
        i++
      }
      else addFlag(flags, name!, true)
      continue
    }

    if (!command) command = arg
    else positional.push(arg)
  }

  return { command, flags, positional }
}

function usage(): string {
  return `ts-sftp ${version} — a zero-dependency SFTP server

Usage:
  ts-sftp serve [options]        Serve a directory over SFTP
  ts-sftp keygen [options]       Generate an Ed25519 host key
  ts-sftp version                Print the version

Serve options:
  --config <path>                Config file (default: sftp.config.ts, if present)
  --port <port>                  Port to listen on (default: 2222)
  --host <address>               Address to bind (default: 0.0.0.0)
  --root <dir>                   Directory to serve (default: the working directory)
  --host-key <path>              Host key file. Generated in memory when omitted
  --user <name>:<authorized_keys path>
                                 Grant a user access using the keys in a file.
                                 Repeatable
  --read-only                    Reject every write
  --verbose                      Log each connection and request

Keygen options:
  --out <path>                   Where to write the key (default: ./ts-sftp_host_ed25519)
  --comment <text>               Comment stored in the key (default: ts-sftp)

Examples:
  ts-sftp keygen --out ./host_key
  ts-sftp serve --root ./uploads --host-key ./host_key --user deploy:./deploy.pub
`
}

async function runKeygen(args: ParsedArgs): Promise<number> {
  const out = resolve(String(args.flags.get('out') ?? './ts-sftp_host_ed25519'))
  const comment = String(args.flags.get('comment') ?? 'ts-sftp')

  const { privateKey, publicKey } = generateHostKeyFiles(comment)
  await mkdir(dirname(out), { recursive: true })
  await writeFile(out, privateKey, { mode: 0o600 })
  await chmod(out, 0o600)
  await writeFile(`${out}.pub`, publicKey, { mode: 0o644 })

  console.log(`Wrote ${out} and ${out}.pub`)
  return 0
}

async function usersFromFlags(args: ParsedArgs): Promise<Record<string, SftpUserConfig>> {
  const raw = args.flags.get('user')
  const entries = raw === undefined ? [] : Array.isArray(raw) ? raw : [raw]
  const users: Record<string, SftpUserConfig> = {}

  for (const entry of entries) {
    if (typeof entry !== 'string') continue
    const separator = entry.indexOf(':')
    if (separator === -1) throw new Error(`--user expects <name>:<authorized_keys path>, got "${entry}"`)

    const username = entry.slice(0, separator)
    const keyPath = entry.slice(separator + 1)
    const text = await readFile(resolve(keyPath), 'utf8')
    users[username] = { publicKeys: text.split('\n').filter((line) => line.trim() && !line.startsWith('#')) }
  }

  return users
}

async function runServe(args: ParsedArgs): Promise<number> {
  const fileConfig = await loadConfig(args.flags.has('config') ? String(args.flags.get('config')) : undefined)
  const cliUsers = await usersFromFlags(args)
  const verbose = args.flags.get('verbose') === true

  const hostKeyPath = args.flags.get('host-key')
  const hostKeys = typeof hostKeyPath === 'string' ? [await readFile(resolve(hostKeyPath), 'utf8')] : fileConfig.hostKeys

  const options: SftpServerOptions = {
    ...fileConfig,
    hostKeys,
    port: args.flags.has('port') ? Number(args.flags.get('port')) : fileConfig.port,
    hostname: args.flags.has('host') ? String(args.flags.get('host')) : fileConfig.hostname,
    root: args.flags.has('root') ? resolve(String(args.flags.get('root'))) : fileConfig.root,
    readOnly: args.flags.get('read-only') === true || fileConfig.readOnly,
    users: { ...fileConfig.users, ...cliUsers },
    logger: {
      info: (message, details) => console.log(`[ts-sftp] ${message}`, details ?? ''),
      warn: (message, details) => console.warn(`[ts-sftp] ${message}`, details ?? ''),
      error: (message, details) => console.error(`[ts-sftp] ${message}`, details ?? ''),
      debug: verbose ? (message, details) => console.log(`[ts-sftp] ${message}`, details ?? '') : undefined,
    },
  }

  if (Object.keys(options.users ?? {}).length === 0) {
    console.error('ts-sftp: no users configured — add --user <name>:<authorized_keys path> or a config file')
    return 1
  }

  const server = new SftpServer(options)
  const running = server.listen()

  console.log(`ts-sftp listening on ${running.hostname}:${running.port}, serving ${options.root}`)
  console.log(`users: ${Object.keys(options.users ?? {}).join(', ')}${options.readOnly ? ' (read-only)' : ''}`)

  const shutdown = (): void => {
    console.log('\nts-sftp shutting down')
    void server.stop().then(() => process.exit(0))
  }
  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)

  // Keep the process alive for as long as the listener is open.
  await new Promise(() => {})
  return 0
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2))

  switch (args.command) {
    case 'serve':
      return await runServe(args)
    case 'keygen':
      return await runKeygen(args)
    case 'version':
    case '--version':
      console.log(version)
      return 0
    case '':
    case 'help':
    case '--help':
      console.log(usage())
      return args.command === '' ? 1 : 0
    default:
      console.error(`ts-sftp: unknown command "${args.command}"\n`)
      console.log(usage())
      return 1
  }
}

main()
  .then((code) => {
    if (code !== 0) process.exitCode = code
  })
  .catch((error: unknown) => {
    console.error(`ts-sftp: ${error instanceof Error ? error.message : String(error)}`)
    process.exitCode = 1
  })
