import { dts } from 'bun-plugin-dtsx'

await Bun.build({
  entrypoints: ['src/index.ts'],
  outdir: './dist',
  target: 'bun',
  plugins: [dts()],
})

// The CLI ships alongside the library so `bunx ts-sftp` works without a build step.
await Bun.build({
  entrypoints: ['bin/cli.ts'],
  outdir: './dist/bin',
  target: 'bun',
})
