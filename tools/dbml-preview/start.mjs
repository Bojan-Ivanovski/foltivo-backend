import { spawn } from 'node:child_process'
import { access, mkdir, rm, symlink } from 'node:fs/promises'
import { constants } from 'node:fs'
import { dirname, isAbsolute, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const appRoot = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(appRoot, '../..')
const requestedFile = process.argv[2]
if (!requestedFile) {
  console.error('Usage: npm start -- <path-to-proposal.dbml>')
  process.exit(2)
}
const dbmlPath = isAbsolute(requestedFile) ? requestedFile : resolve(repoRoot, requestedFile)
const publicDirectory = resolve(appRoot, 'public')
const sourceLink = resolve(publicDirectory, 'schema.dbml')

try {
  await access(dbmlPath, constants.R_OK)
} catch {
  console.error(`Cannot read DBML file: ${dbmlPath}`)
  console.error('Pass a path to an existing proposal, relative to the backend repository root or absolute.')
  process.exit(1)
}

await mkdir(publicDirectory, { recursive: true })
await rm(sourceLink, { force: true })
await symlink(dbmlPath, sourceLink)

console.log(`DBML source: ${dbmlPath}`)
console.log('Starting preview at http://localhost:4173')
console.log('Stop the preview with Ctrl+C.')

const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm'
const server = spawn(npmCommand, ['run', 'dev'], {
  cwd: appRoot,
  stdio: 'inherit',
})

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.kill(signal))
}

server.on('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal)
  process.exit(code ?? 0)
})
