# Installation

```bash
bun add ts-sftp
```

Or install the CLI globally:

```bash
bun add -g ts-sftp
```

Standalone binaries for Linux, macOS, and Windows are attached to each
[release](https://github.com/stacksjs/ts-sftp/releases), so a server can run
without a Bun install:

```bash
curl -L https://github.com/stacksjs/ts-sftp/releases/latest/download/ts-sftp-linux-x64.zip -o ts-sftp.zip
unzip ts-sftp.zip && chmod +x ts-sftp-linux-x64
```

## Requirements

Bun 1.2 or newer, and no native modules. The only runtime dependency is
`@stacksjs/clapp`, used by the CLI; it has no dependencies of its own, so the
installed tree is two packages deep at most.
