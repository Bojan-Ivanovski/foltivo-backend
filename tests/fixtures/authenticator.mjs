// Chromium's maintained CTAP2 virtual authenticator; no application verification
// is stubbed. JSON-lines adapter so the Cargo suite owns browser lifetime.
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:http';
import { createInterface } from 'node:readline';
import { createPrivateKey } from 'node:crypto';

let chrome = process.env.FOLTIVO_TEST_CHROMIUM;
if (!chrome) {
  for (const name of ['google-chrome', 'chromium', 'chromium-browser']) {
    const path = spawnSync('which', [name], { encoding: 'utf8' });
    if (path.status === 0) { chrome = path.stdout.trim(); break; }
  }
}
if (!chrome) {
  const cache = join(homedir(), '.cache/ms-playwright');
  if (existsSync(cache)) {
    for (const name of readdirSync(cache).filter(n => n.startsWith('chromium-')).sort().reverse()) {
      for (const suffix of ['chrome-linux64/chrome', 'chrome-linux/chrome']) {
        const candidate = join(cache, name, suffix);
        if (existsSync(candidate)) { chrome = candidate; break; }
      }
      if (chrome) break;
    }
  }
}
if (!chrome) throw new Error('Install Chromium/Chrome or set FOLTIVO_TEST_CHROMIUM; signed passkey tests cannot be skipped.');
const profile = mkdtempSync(join(tmpdir(), 'foltivo-authenticator-'));
const browser = spawn(chrome, ['--headless=new', '--no-sandbox', '--disable-dev-shm-usage', '--disable-background-networking', '--disable-component-update', '--no-first-run', '--remote-debugging-pipe', `--user-data-dir=${profile}`], { stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] });
let seq = 0, pending = new Map(), buffer = '';
browser.stdio[4].on('data', chunk => {
  buffer += chunk.toString();
  for (;;) {
    const boundary = buffer.indexOf('\0'); if (boundary < 0) break;
    const message = JSON.parse(buffer.slice(0, boundary)); buffer = buffer.slice(boundary + 1);
    if (message.id) {
      const request = pending.get(message.id); pending.delete(message.id);
      if (message.error) request?.reject(new Error(JSON.stringify(message.error))); else request?.resolve(message.result);
    }
  }
});
browser.on('exit', (code, signal) => {
  for (const request of pending.values()) request.reject(new Error(`Chromium exited ${code}/${signal}`));
});
function cdp(method, params = {}, sessionId) {
  const id = ++seq;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    browser.stdio[3].write(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }) + '\0');
  });
}
const server = createServer((request, response) => { response.writeHead(200, { 'Content-Type': 'text/html' }); response.end('<!doctype html><title>Foltivo isolated authenticator</title>'); });
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://localhost:${server.address().port}`;
const { targetId } = await cdp('Target.createTarget', { url: origin });
const { sessionId } = await cdp('Target.attachToTarget', { targetId, flatten: true });
await cdp('Runtime.enable', {}, sessionId);
await cdp('WebAuthn.enable', { enableUI: false }, sessionId);
const { authenticatorId } = await cdp('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } }, sessionId);
// Avoid racing Target.createTarget navigation.
for (let i = 0; i < 100; i++) {
  const result = await cdp('Runtime.evaluate', { expression: 'location.origin' }, sessionId);
  if (result.result.value === origin) break;
  if (i === 99) throw new Error('authenticator page did not navigate');
  await new Promise(resolve => setTimeout(resolve, 10));
}
console.log(JSON.stringify({ origin }));
const input = createInterface({ input: process.stdin });
async function cleanup() {
  server.close(); browser.kill('SIGTERM');
  await new Promise(resolve => { if (browser.exitCode !== null) resolve(); else { browser.once('exit', resolve); setTimeout(resolve, 2000).unref(); } });
  rmSync(profile, { recursive: true, force: true });
}
process.on('SIGTERM', async () => { await cleanup(); process.exit(0); });
for await (const line of input) {
  try {
    const command = JSON.parse(line);
    if (command.action === 'close') { console.log('{}'); break; }
    if (command.action === 'verified') {
      await cdp('WebAuthn.setUserVerified', { authenticatorId, isUserVerified: command.options }, sessionId);
      console.log('{}'); continue;
    }
    if (command.action === 'override') {
      await cdp('WebAuthn.setResponseOverrideBits', { authenticatorId, ...command.options }, sessionId);
      console.log('{}'); continue;
    }
    if (command.action === 'add') {
      await cdp('WebAuthn.addCredential', { authenticatorId, credential: command.options }, sessionId);
      console.log('{}'); continue;
    }
    if (command.action === 'credentials') {
      const result = await cdp('WebAuthn.getCredentials', { authenticatorId }, sessionId);
      result.credentials = result.credentials.map(c => ({ ...c, publicJwk: createPrivateKey({ key: Buffer.from(c.privateKey, 'base64'), type: 'pkcs8', format: 'der' }).export({ format: 'jwk' }) }));
      console.log(JSON.stringify(result)); continue;
    }
    const registration = command.action === 'register';
    const expression = `(async () => {
      const options = ${JSON.stringify(command.options)};
      const decode = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
      const encode = b => b ? btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '') : null;
      const publicKey = options.publicKey;
      publicKey.challenge = decode(publicKey.challenge);
      publicKey.timeout = 2000;
      if (publicKey.user) publicKey.user.id = decode(publicKey.user.id);
      for (const name of ['allowCredentials','excludeCredentials']) if (publicKey[name]) publicKey[name] = publicKey[name].map(c => ({...c,id:decode(c.id)}));
      const credential = await navigator.credentials.${registration ? 'create' : 'get'}({publicKey});
      const response = credential.response;
      return { id:credential.id, rawId:encode(credential.rawId), type:credential.type,
        response: {clientDataJSON:encode(response.clientDataJSON), ${registration ? 'attestationObject:encode(response.attestationObject)' : 'authenticatorData:encode(response.authenticatorData),signature:encode(response.signature),userHandle:encode(response.userHandle)'}},
        clientExtensionResults:credential.getClientExtensionResults() };
    })()`;
    const result = await cdp('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, sessionId);
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    console.log(JSON.stringify(result.result.value));
  } catch (error) { console.log(JSON.stringify({ error: String(error) })); }
}
await cleanup();

input.close();
process.stdin.destroy();
