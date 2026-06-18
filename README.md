<div align="center">

# jwt-decode

**Inspect JWT tokens in your terminal — claims, expiry, formats. No secrets. Zero dependencies.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue?labelColor=0B0A09)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18-green?labelColor=0B0A09)](https://nodejs.org)
[![Zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen?labelColor=0B0A09)](#)

</div>

## Install

```bash
npx github:NickCirv/jwt-decode <token>
```

Or install globally:

```bash
npm install -g github:NickCirv/jwt-decode
```

Requires Node.js >= 18.

## Usage

```bash
# Decode from argument (default tree view)
jwt-decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# From stdin
echo "$TOKEN" | jwt-decode

# From file
jwt-decode --file token.txt

# From clipboard (pbpaste / xclip / xsel)
jwt-decode --clipboard
```

| Flag | Description |
|------|-------------|
| `--format tree\|table\|json` | Output format (default: tree) |
| `--json` | Shorthand for `--format json` |
| `--claim <key>` | Extract a single claim value |
| `--check-expiry` | Exit 1 if expired, exit 0 if valid |
| `--no-color` | Disable color output |
| `--help`, `-h` | Show help |

## What it does

Decodes the header and payload of any JWT token and prints them in a color-coded tree, table, or JSON format. Timestamps (`iat`, `exp`, `nbf`) are shown as human-readable dates with relative time. The `--check-expiry` flag makes it useful in shell scripts to gate on token validity. Signature is **never verified** — no secret or key is required.

---
<sub>Zero dependencies · Node >=18 · MIT · by <a href="https://github.com/NickCirv">NickCirv</a></sub>
