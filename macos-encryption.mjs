import { execFile } from 'node:child_process';

export function createMacOSCredentialEncryption(helper, { canaryAccount } = {}) {
  async function run(operation, input) {
    const args = canaryAccount === undefined ? [operation] : [operation, canaryAccount];
    return new Promise((resolve, reject) => {
      const child = execFile(helper, args, {
        encoding: 'buffer', timeout: 15_000, maxBuffer: 4 * 1024 * 1024,
      }, (error, stdout) => {
        if (error) reject(new Error('macOS Keychain operation failed'));
        else resolve(stdout);
      });
      child.stdin.on('error', error => {
        if (error.code !== 'EPIPE') reject(new Error('macOS Keychain pipe failed'));
      });
      child.stdin.end(input);
    });
  }

  return {
    id: 'macos-keychain-aes-gcm-gptr-v1',
    async isAvailable() {
      if (process.platform !== 'darwin') return false;
      try {
        await run('check');
        return true;
      } catch {
        return false;
      }
    },
    encrypt: plaintext => run('encrypt', Buffer.from(plaintext, 'utf8')),
    decrypt: async ciphertext => (await run('decrypt', Buffer.from(ciphertext))).toString('utf8'),
  };
}
