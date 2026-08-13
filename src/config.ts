/**
 * Configuration loading for the CLI.
 *
 * A config file is a TypeScript module exporting an {@link SftpServerOptions}
 * object — no schema language, no runtime dependency, and the same types the
 * library takes.
 */

import type { SftpServerOptions } from './types'
import { isAbsolute, resolve } from 'node:path'

/** Config file names looked for, in order. */
export const CONFIG_FILE_NAMES: string[] = ['sftp.config.ts', 'sftp.config.js', 'ts-sftp.config.ts', 'ts-sftp.config.js']

/** Defaults applied when a field is left out. */
export const defaultConfig: SftpServerOptions = {
  port: 2222,
  hostname: '0.0.0.0',
  root: process.cwd(),
  users: {},
}

/** Identity helper that gives a config file type checking and completion. */
export function defineConfig(config: SftpServerOptions): SftpServerOptions {
  return config
}

/**
 * Load a config file. Returns the defaults when `path` is omitted and no config
 * file is found next to the process's working directory.
 */
export async function loadConfig(path?: string, cwd: string = process.cwd()): Promise<SftpServerOptions> {
  const candidates = path ? [isAbsolute(path) ? path : resolve(cwd, path)] : CONFIG_FILE_NAMES.map((name) => resolve(cwd, name))

  for (const candidate of candidates) {
    if (!(await Bun.file(candidate).exists())) continue

    const module = (await import(candidate)) as { default?: SftpServerOptions } & SftpServerOptions
    const loaded = module.default ?? module
    return { ...defaultConfig, ...loaded }
  }

  if (path) throw new Error(`ts-sftp: config file not found: ${path}`)
  return { ...defaultConfig }
}
