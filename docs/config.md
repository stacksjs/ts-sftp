# Configuration

The CLI reads `sftp.config.ts` from the working directory, or the file given
with `--config`. The config is a plain TypeScript module exporting the same
options the library takes.

```ts
// sftp.config.ts
import { defineConfig } from 'ts-sftp'

export default defineConfig({
  port: 2222,
  hostname: '0.0.0.0',
  root: './uploads',
  hostKeys: [await Bun.file('/etc/ts-sftp/host_key').text()],
  users: {
    deploy: {
      publicKeys: ['ssh-ed25519 AAAAC3Nz... deploy@example.com'],
      root: './uploads/incoming',
    },
    viewer: {
      publicKeys: ['ssh-ed25519 AAAAC3Nz... viewer@example.com'],
      readOnly: true,
    },
  },
})
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `port` | `number` | `2222` | Port to listen on. `0` binds a free port |
| `hostname` | `string` | `0.0.0.0` | Address to bind |
| `hostKeys` | `(string \| HostKey)[]` | generated | Host key text (OpenSSH or PEM). Only Ed25519 keys are supported |
| `root` | `string` | `process.cwd()` | Directory served to users without their own root |
| `users` | `Record<string, SftpUserConfig>` | `{}` | Users the built-in authenticator accepts |
| `authenticate` | `(context) => boolean` | built-in | Custom authentication, run after signature verification |
| `createFileSystem` | `(context) => SftpFileSystem` | local disk | Storage for a session |
| `readOnly` | `boolean` | `false` | Reject every write, for every user |
| `maxConnections` | `number` | `100` | Concurrent sessions before new ones are refused |
| `authTimeoutMs` | `number` | `30000` | Time a connection may spend unauthenticated |
| `maxAuthAttempts` | `number` | `6` | Failed attempts before disconnect, like sshd's `MaxAuthTries` |
| `logger` | `SftpLogger` | warns + errors | Log sink |

## Per-user options

| Option | Type | Description |
| --- | --- | --- |
| `publicKeys` | `(string \| SshPublicKey)[]` | `authorized_keys` lines this user may authenticate with |
| `password` | `string` | Accepted password. Keys are the better choice |
| `root` | `string` | Directory this user is confined to |
| `readOnly` | `boolean` | Reject writes for this user only |

## Host keys

Generate one with the CLI, or with `ssh-keygen -t ed25519`:

```bash
ts-sftp keygen --out /etc/ts-sftp/host_key
```

Keys must be unencrypted — the server has no passphrase to prompt for. Decrypt
an existing key with `ssh-keygen -p -f ./host_key`.
