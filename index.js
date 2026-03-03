#!/usr/bin/env node
/**
 * jwt-decode — Decode and inspect JWT tokens
 * Zero external dependencies. Never verifies signatures.
 */

import { readFileSync } from 'fs';
import { spawnSync } from 'child_process';
import { createInterface } from 'readline';
import { Buffer } from 'buffer';

// ── ANSI colors ──────────────────────────────────────────────────────────────
const C = {
  reset:  '\x1b[0m',
  bold:   '\x1b[1m',
  dim:    '\x1b[2m',
  red:    '\x1b[31m',
  green:  '\x1b[32m',
  yellow: '\x1b[33m',
  blue:   '\x1b[34m',
  cyan:   '\x1b[36m',
  white:  '\x1b[37m',
  gray:   '\x1b[90m',
  bgRed:  '\x1b[41m',
};

const NO_COLOR = process.env.NO_COLOR || !process.stdout.isTTY;

function c(color, text) {
  if (NO_COLOR) return text;
  return `${color}${text}${C.reset}`;
}

// ── Base64url decode ──────────────────────────────────────────────────────────
function decodeBase64url(str) {
  // Pad base64url to standard base64
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const remainder = padded.length % 4;
  const padding = remainder === 0 ? '' : '='.repeat(4 - remainder);
  return Buffer.from(padded + padding, 'base64').toString('utf8');
}

// ── JWT parse ─────────────────────────────────────────────────────────────────
function parseJWT(token) {
  const trimmed = token.trim();
  const parts = trimmed.split('.');

  if (parts.length !== 3) {
    throw new Error(`Malformed JWT: expected 3 parts separated by '.', got ${parts.length}`);
  }

  const [rawHeader, rawPayload, rawSignature] = parts;

  let header, payload;

  try {
    header = JSON.parse(decodeBase64url(rawHeader));
  } catch {
    throw new Error('Malformed JWT: could not decode header — invalid base64url or JSON');
  }

  try {
    payload = JSON.parse(decodeBase64url(rawPayload));
  } catch {
    throw new Error('Malformed JWT: could not decode payload — invalid base64url or JSON');
  }

  return {
    header,
    payload,
    signature: rawSignature,
    raw: { header: rawHeader, payload: rawPayload, signature: rawSignature },
    stats: {
      total: trimmed.length,
      header: rawHeader.length,
      payload: rawPayload.length,
      signature: rawSignature.length,
    },
  };
}

// ── Time formatting ───────────────────────────────────────────────────────────
function formatTimestamp(unix) {
  const date = new Date(unix * 1000);
  const iso = date.toISOString().replace('T', ' ').replace('.000Z', ' UTC');
  const now = Math.floor(Date.now() / 1000);
  const diff = unix - now;
  const abs = Math.abs(diff);

  const days    = Math.floor(abs / 86400);
  const hours   = Math.floor((abs % 86400) / 3600);
  const minutes = Math.floor((abs % 3600) / 60);
  const seconds = abs % 60;

  let relative;
  if (abs < 60) {
    relative = diff > 0 ? `expires in ${seconds}s` : `EXPIRED ${seconds}s ago`;
  } else if (abs < 3600) {
    relative = diff > 0 ? `expires in ${minutes}m ${seconds}s` : `EXPIRED ${minutes}m ago`;
  } else if (abs < 86400) {
    relative = diff > 0 ? `expires in ${hours}h ${minutes}m` : `EXPIRED ${hours}h ${minutes}m ago`;
  } else {
    const dayStr = days === 1 ? '1 day' : `${days} days`;
    relative = diff > 0 ? `expires in ${dayStr}` : `EXPIRED ${dayStr} ago`;
  }

  return { iso, relative, unix, expired: diff < 0, soonExpiry: diff > 0 && diff < 900 };
}

// ── Claim formatting ──────────────────────────────────────────────────────────
const TIME_CLAIMS = new Set(['iat', 'exp', 'nbf']);
const STANDARD_CLAIMS = {
  sub:   'Subject',
  iss:   'Issuer',
  aud:   'Audience',
  jti:   'JWT ID',
  iat:   'Issued At',
  exp:   'Expires',
  nbf:   'Not Before',
  scope: 'Scope',
  email: 'Email',
  name:  'Name',
  roles: 'Roles',
};

function formatClaimValue(key, value) {
  if (TIME_CLAIMS.has(key) && typeof value === 'number') {
    const t = formatTimestamp(value);
    let color = C.green;
    let tag = '';
    if (key === 'exp') {
      if (t.expired) { color = C.red; tag = ' ⚠ EXPIRED'; }
      else if (t.soonExpiry) { color = C.yellow; tag = ' ⚠ expiring soon'; }
    }
    return { display: `${c(color, t.iso)}  ${c(C.dim, `(${t.relative}${tag})`)}`, timeInfo: t };
  }

  if (Array.isArray(value)) return { display: value.join(', ') };
  if (typeof value === 'object' && value !== null) return { display: JSON.stringify(value) };
  if (typeof value === 'boolean') return { display: c(value ? C.green : C.yellow, String(value)) };

  return { display: String(value) };
}

// ── Output: tree ──────────────────────────────────────────────────────────────
function renderTree(jwt) {
  const { header, payload, signature, stats } = jwt;
  const lines = [];

  // Stats bar
  lines.push('');
  lines.push(c(C.bold + C.cyan, '── JWT Token ────────────────────────────────────────────────────'));
  lines.push(c(C.dim, `   Total: ${stats.total}B  │  Header: ${stats.header}B  │  Payload: ${stats.payload}B  │  Signature: ${stats.signature}B`));
  lines.push('');

  // Expiry check — prominent banner
  const expInfo = payload.exp ? formatTimestamp(payload.exp) : null;
  if (expInfo?.expired) {
    lines.push(c(C.bgRed + C.bold, '  ⚠  TOKEN EXPIRED  ⚠  '));
    lines.push('');
  } else if (expInfo?.soonExpiry) {
    lines.push(c(C.yellow + C.bold, '  ⚠  TOKEN EXPIRING SOON  '));
    lines.push('');
  }

  // Header section
  lines.push(c(C.cyan + C.bold, '┌─ Header'));
  const headerFields = [
    ['alg', 'Algorithm', header.alg],
    ['typ', 'Type',      header.typ],
    ['kid', 'Key ID',    header.kid],
  ];
  for (const [k, label, val] of headerFields) {
    if (val !== undefined) {
      lines.push(`│  ${c(C.gray, label.padEnd(12))}  ${c(C.cyan, String(val))}`);
    }
  }
  // Extra header claims
  for (const [k, v] of Object.entries(header)) {
    if (!['alg', 'typ', 'kid'].includes(k)) {
      lines.push(`│  ${c(C.gray, k.padEnd(12))}  ${String(v)}`);
    }
  }
  lines.push('│');

  // Payload section
  lines.push(c(C.blue + C.bold, '├─ Payload'));
  for (const [k, v] of Object.entries(payload)) {
    const label = STANDARD_CLAIMS[k] || k;
    const { display } = formatClaimValue(k, v);
    lines.push(`│  ${c(C.gray, label.padEnd(12))}  ${display}`);
  }
  lines.push('│');

  // Signature section
  lines.push(c(C.gray + C.bold, '└─ Signature'));
  lines.push(`   ${c(C.dim, `Algorithm: ${header.alg || 'unknown'}`)}`);
  lines.push(`   ${c(C.yellow, 'NOT VERIFIED — decode only, no secret used')}`);
  lines.push(`   ${c(C.dim, jwt.raw.signature.slice(0, 40) + '...')}`);
  lines.push('');

  return lines.join('\n');
}

// ── Output: table ──────────────────────────────────────────────────────────────
function renderTable(jwt) {
  const { header, payload } = jwt;
  const rows = [];

  rows.push(['Section', 'Claim', 'Value']);
  rows.push(['-------', '-----', '-----']);

  for (const [k, v] of Object.entries(header)) {
    rows.push(['header', k, String(v)]);
  }

  for (const [k, v] of Object.entries(payload)) {
    const { display } = formatClaimValue(k, v);
    rows.push(['payload', k, display]);
  }

  rows.push(['signature', 'status', 'NOT VERIFIED']);
  rows.push(['signature', 'algorithm', header.alg || 'unknown']);

  const widths = [0, 0, 0];
  for (const row of rows) {
    // Strip ANSI for width measurement
    for (let i = 0; i < 3; i++) {
      const plain = row[i].replace(/\x1b\[[0-9;]*m/g, '');
      widths[i] = Math.max(widths[i], plain.length);
    }
  }

  const lines = ['\n'];
  for (const row of rows) {
    const plain = row.map(cell => cell.replace(/\x1b\[[0-9;]*m/g, ''));
    const padded = row.map((cell, i) => cell + ' '.repeat(widths[i] - plain[i].length));
    lines.push(`  ${padded.join('  ')}`);
  }
  lines.push('');
  return lines.join('\n');
}

// ── Output: JSON ──────────────────────────────────────────────────────────────
function renderJSON(jwt) {
  const out = {
    header: jwt.header,
    payload: jwt.payload,
    signature: {
      algorithm: jwt.header.alg || 'unknown',
      verified: false,
      note: 'Signature not verified — decode only',
    },
    stats: jwt.stats,
  };
  return JSON.stringify(out, null, 2);
}

// ── Input sources ─────────────────────────────────────────────────────────────
async function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    const rl = createInterface({ input: process.stdin });
    rl.on('line', line => { data += line; });
    rl.on('close', () => resolve(data.trim()));
    rl.on('error', reject);
  });
}

function readClipboard() {
  const platform = process.platform;
  let cmd, args;

  if (platform === 'darwin') {
    cmd = 'pbpaste'; args = [];
  } else if (platform === 'linux') {
    // Try xclip first, then xsel
    const xclip = spawnSync('which', ['xclip'], { encoding: 'utf8' });
    if (xclip.status === 0) {
      cmd = 'xclip'; args = ['-selection', 'clipboard', '-o'];
    } else {
      cmd = 'xsel'; args = ['--clipboard', '--output'];
    }
  } else if (platform === 'win32') {
    cmd = 'powershell'; args = ['-command', 'Get-Clipboard'];
  } else {
    throw new Error(`Clipboard not supported on platform: ${platform}`);
  }

  const result = spawnSync(cmd, args, { encoding: 'utf8' });
  if (result.error) throw new Error(`Clipboard read failed: ${result.error.message}`);
  if (result.status !== 0) throw new Error(`Clipboard command failed (exit ${result.status})`);
  return (result.stdout || '').trim();
}

// ── Help ──────────────────────────────────────────────────────────────────────
function printHelp() {
  console.log(`
${c(C.bold, 'jwt-decode')} — Decode and inspect JWT tokens. ${c(C.yellow, 'Never verifies signatures.')}

${c(C.bold, 'USAGE')}
  jwt-decode <token>                     Decode token from argument
  echo "<token>" | jwt-decode            Decode from stdin
  jwt-decode --file <path>               Read token from file
  jwt-decode --clipboard                 Read token from clipboard

${c(C.bold, 'OPTIONS')}
  --format <tree|table|json>             Output format (default: tree)
  --json                                 Shorthand for --format json
  --claim <key>                          Extract a single claim value
  --check-expiry                         Exit 1 if expired, 0 if valid
  --no-color                             Disable color output
  --help, -h                             Show this help

${c(C.bold, 'EXAMPLES')}
  jwt-decode eyJhbGci...
  jwt-decode eyJhbGci... --format table
  jwt-decode eyJhbGci... --claim sub
  jwt-decode eyJhbGci... --check-expiry && echo "Token is valid"
  jwt-decode --file token.txt
  jwt-decode --clipboard --json

${c(C.bold, 'SECURITY')}
  ${c(C.yellow, '• Signature is NOT verified — this tool decodes only')}
  • No secrets or keys are ever required or used
  • Tokens from arguments are decoded in-memory and never logged

${c(C.bold, 'ALIASES')}
  jwtd  (shorthand alias)
`);
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    printHelp();
    process.exit(0);
  }

  // Handle --no-color flag
  if (args.includes('--no-color')) {
    process.env.NO_COLOR = '1';
  }

  // Parse flags
  let format = 'tree';
  let claimKey = null;
  let checkExpiry = false;
  let tokenArg = null;
  let fromFile = null;
  let fromClipboard = false;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--json') { format = 'json'; }
    else if (a === '--format' && args[i + 1]) { format = args[++i]; }
    else if (a === '--claim' && args[i + 1]) { claimKey = args[++i]; }
    else if (a === '--check-expiry') { checkExpiry = true; }
    else if (a === '--file' && args[i + 1]) { fromFile = args[++i]; }
    else if (a === '--clipboard') { fromClipboard = true; }
    else if (a === '--no-color') { /* handled above */ }
    else if (!a.startsWith('--')) { tokenArg = a; }
  }

  if (!['tree', 'table', 'json'].includes(format)) {
    console.error(`Error: unknown format "${format}". Use tree, table, or json.`);
    process.exit(1);
  }

  // Acquire token
  let token;

  try {
    if (fromClipboard) {
      token = readClipboard();
      if (!token) throw new Error('Clipboard is empty');
    } else if (fromFile) {
      token = readFileSync(fromFile, 'utf8').trim();
      if (!token) throw new Error(`File is empty: ${fromFile}`);
    } else if (tokenArg) {
      token = tokenArg;
    } else if (!process.stdin.isTTY) {
      token = await readStdin();
      if (!token) throw new Error('No token received from stdin');
    } else {
      printHelp();
      process.exit(0);
    }
  } catch (err) {
    console.error(`${c(C.red, 'Error:')} ${err.message}`);
    process.exit(1);
  }

  // Parse JWT
  let jwt;
  try {
    jwt = parseJWT(token);
  } catch (err) {
    console.error(`${c(C.red, 'Error:')} ${err.message}`);
    process.exit(1);
  }

  // --check-expiry mode
  if (checkExpiry) {
    const exp = jwt.payload.exp;
    if (exp === undefined) {
      console.error(c(C.yellow, 'Warning: token has no exp claim — cannot determine expiry'));
      process.exit(0);
    }
    const now = Math.floor(Date.now() / 1000);
    if (exp < now) {
      const t = formatTimestamp(exp);
      console.error(c(C.red, `Token EXPIRED: ${t.iso} (${t.relative})`));
      process.exit(1);
    } else {
      const t = formatTimestamp(exp);
      console.log(c(C.green, `Token valid. Expires: ${t.iso} (${t.relative})`));
      process.exit(0);
    }
  }

  // --claim mode
  if (claimKey) {
    const value = jwt.payload[claimKey] ?? jwt.header[claimKey];
    if (value === undefined) {
      console.error(`${c(C.red, 'Error:')} claim "${claimKey}" not found in header or payload`);
      process.exit(1);
    }
    if (TIME_CLAIMS.has(claimKey) && typeof value === 'number') {
      const t = formatTimestamp(value);
      console.log(`${value}  (${t.iso} — ${t.relative})`);
    } else if (typeof value === 'object') {
      console.log(JSON.stringify(value));
    } else {
      console.log(value);
    }
    process.exit(0);
  }

  // Full output
  if (format === 'json') {
    console.log(renderJSON(jwt));
  } else if (format === 'table') {
    console.log(renderTable(jwt));
  } else {
    console.log(renderTree(jwt));
  }
}

main().catch(err => {
  console.error(`${'\x1b[31m'}Unexpected error:${'\x1b[0m'} ${err.message}`);
  process.exit(1);
});
