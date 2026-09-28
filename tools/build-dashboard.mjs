// Encrypts dashboard-src/dashboard.html into dashboard/index.html behind a
// username + password login. The source stays out of git (the repo is public);
// only the encrypted page is published.
//
// Usage:  node tools/build-dashboard.mjs
// (or set A2E_DASH_USER and A2E_DASH_PASS to skip the prompts)
//
//         node tools/build-dashboard.mjs --generate [username]
// creates a random password and saves the login to dashboard-src/LOGIN-DETAILS.txt

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { webcrypto as crypto } from 'node:crypto';
import readline from 'node:readline';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = path.join(ROOT, 'dashboard-src', 'dashboard.html');
const OUT_DIR = path.join(ROOT, 'dashboard');
const ITERATIONS = 600000;

function ask(question, hidden) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  if (hidden) {
    rl._writeToOutput = (s) => { if (s.includes(question)) rl.output.write(s); };
  }
  return new Promise((resolve) => rl.question(question, (answer) => {
    rl.close();
    if (hidden) process.stdout.write('\n');
    resolve(answer);
  }));
}

// Must match keyMaterial() in the login page
function keyMaterial(user, pass) {
  return user.trim().toLowerCase() + '\n' + pass;
}

const b64 = (buf) => Buffer.from(buf).toString('base64');

// Readable random password, e.g. "k7Qm-xR2p-Vw9d-Hn4t"
function generatePassword() {
  const chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const s = Array.from(bytes, (b) => chars[b % chars.length]).join('');
  return s.match(/.{4}/g).join('-');
}

async function main() {
  const genIndex = process.argv.indexOf('--generate');
  let user, pass;
  if (genIndex !== -1) {
    user = process.argv[genIndex + 1] || 'uts-grant';
    pass = generatePassword();
  } else {
    user = process.env.A2E_DASH_USER || await ask('Dashboard username: ');
    pass = process.env.A2E_DASH_PASS || await ask('Dashboard password: ', true);
  }
  if (!user.trim() || pass.length < 10) {
    console.error('Username is required and the password must be at least 10 characters.');
    process.exit(1);
  }

  const html = await readFile(SRC, 'utf8');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(keyMaterial(user, pass)), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
  );
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(html));

  const payload = JSON.stringify({ salt: b64(salt), iv: b64(iv), iter: ITERATIONS, data: b64(cipher) });
  const template = await readFile(path.join(ROOT, 'tools', 'dashboard-login.html'), 'utf8');
  await mkdir(OUT_DIR, { recursive: true });
  await writeFile(path.join(OUT_DIR, 'index.html'), template.replace('/*PAYLOAD*/null', payload));
  console.log('Built dashboard/index.html (encrypted).');

  if (genIndex !== -1) {
    const details = path.join(ROOT, 'dashboard-src', 'LOGIN-DETAILS.txt');
    await writeFile(details,
      'Air2Energy UTS dashboard login\n\n' +
      'Link:     https://air2energy.net/dashboard/\n' +
      'Username: ' + user + '\n' +
      'Password: ' + pass + '\n');
    console.log('Login details saved to dashboard-src/LOGIN-DETAILS.txt');
  }
}

main().catch((err) => { console.error(err); process.exit(1); });
