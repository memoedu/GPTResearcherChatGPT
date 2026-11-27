import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createMacOSCredentialEncryption } from './macos-encryption.mjs';

// Use a synthetic entry in the actual login Keychain and state in a private scratch directory.
const [runtime, helper, phase, directory, account] = process.argv.slice(2);
assert.equal(process.platform, 'darwin');
assert.ok(runtime && helper, 'Usage: node verify-macos-keychain.mjs <absolute-runtime> <absolute-helper>');
const service = 'org.memoedu.gpt-researcher.chatgpt';
const value = 'synthetic-永不用于登录-' + 'Q7M4';
const state = {
  version: 2, activeProfileId: 'synthetic-profile', pendingRegistrations: [],
  profiles: [{
    version: 1, id: 'synthetic-profile', label: 'Synthetic profile', clientId: 'synthetic-client',
    status: 'connected', scopes: ['openid', 'chatgpt.tokens.use.direct'],
    savedAt: '2026-01-01T00:00:00.000Z', subject: 'synthetic-subject',
    profileIdToken: value,
    credentials: { accessToken: value, refreshToken: value, expiresAt: 4102444800000 },
  }],
};

if (!phase) {
  const scratch = await mkdtemp(join(tmpdir(), 'gptr-keychain-canary-'));
  const syntheticAccount = randomUUID();
  const keychain = JSON.parse(execFileSync('/usr/bin/security', ['default-keychain', '-d', 'user'], {
    encoding: 'utf8', timeout: 15_000,
  }).trim());
  try {
    const run = stage => execFileSync(process.execPath, [
      fileURLToPath(import.meta.url), runtime, helper, stage, scratch, syntheticAccount,
    ], { encoding: 'utf8', timeout: 60_000 });
    const first = JSON.parse(run('write'));
    const second = JSON.parse(run('restore'));
    assert.deepEqual(second, first);
    console.log(JSON.stringify({ provider: first.provider, encryptedEnvelopeVersion: first.version,
      ownerOnly: true, separateProcesses: true, tamperRejected: true, missingKeyRejected: true,
      providerMismatchPreserved: true, ciphertextPreserved: true }, null, 2));
  } finally {
    try {
      execFileSync('/usr/bin/security', [
        'delete-generic-password', '-s', service, '-a', 'canary-' + syntheticAccount, keychain,
      ], { stdio: 'ignore', timeout: 15_000 });
    } finally {
      await rm(scratch, { recursive: true, force: true });
    }
  }
} else {
  assert.ok(phase === 'write' || phase === 'restore');
  const { ConnectionStore } = await import(pathToFileURL(join(runtime,
    'siwc/node_modules/@siwc/local/dist/storage.js')).href);
  const encryption = createMacOSCredentialEncryption(helper, { canaryAccount: account });
  const store = new ConnectionStore(directory, encryption);
  const file = join(directory, 'chatgpt-auth.json');
  assert.equal(await encryption.isAvailable(), true);
  if (phase === 'write') {
    await store.withLock(() => store.write(state));
  } else {
    const raw = await readFile(file);
    const original = JSON.parse(raw);
    const damaged = Buffer.from(original.ciphertext, 'base64');
    damaged[damaged.length - 1] ^= 1;
    await assert.rejects(encryption.decrypt(damaged));
    const missingKey = createMacOSCredentialEncryption(helper, { canaryAccount: randomUUID() });
    await assert.rejects(missingKey.decrypt(Buffer.from(original.ciphertext, 'base64')));
    const otherProvider = new ConnectionStore(directory, { ...encryption, id: 'synthetic-other-provider' });
    await assert.rejects(otherProvider.withLock(() => otherProvider.read()), { code: 'storage_provider_mismatch' });
    assert.deepEqual(await readFile(file), raw);
  }
  assert.deepEqual((await store.withLock(() => store.read())).profiles[0].credentials, state.profiles[0].credentials);
  const raw = await readFile(file);
  const envelope = JSON.parse(raw);
  assert.equal(envelope.version, 3);
  assert.equal(envelope.provider, encryption.id);
  assert.equal(raw.includes(Buffer.from(value)), false);
  assert.equal((await stat(file)).mode & 0o777, 0o600);
  assert.deepEqual(await readdir(directory), ['chatgpt-auth.json']);
  console.log(JSON.stringify(envelope));
}
